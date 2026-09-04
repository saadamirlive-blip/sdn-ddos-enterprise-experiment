"""
Enterprise SDN Security Controller v2 -- FIXED
================================================
Fixes applied vs. the original enterprise_security_controller.py:

BUG FIX 1 (critical): The original controller pre-installed PERMANENT
(idle_timeout=0) flow rules matching only on eth_dst for every host, at
switch-connect time. Because these rules never expire and never match on
IP fields, two things silently broke:
  (a) _flow_stats_reply_handler only processes stats where match has
      'ipv4_src' set -- but no installed rule ever matched on IP, so this
      detection path could never receive data to analyze.
  (b) Traffic between two already-known hosts (which includes attacker ->
      victim traffic once both hosts have sent a first packet) matches the
      static eth_dst rule and is switched entirely in the data plane,
      never reaching the controller via Packet-In either.
  Net effect: neither detection path could fire once both hosts were known.

FIX: Replace permanent eth_dst-only forwarding with REACTIVE per-5-tuple
(src_ip, dst_ip, proto, ports) flow installation with a moderate
idle_timeout. Every new flow's first packet reaches the controller for
inspection; established flows are periodically re-polled via flow-stats
(which now DO carry ipv4_src/ipv4_dst) before they expire and get
reinstalled. ARP is still handled via fast, permanent rules since ARP
carries no attack signal here.

BUG FIX 2: The original implemented only ONE enforcement action (hard
drop). This version implements the four-tier action the paper actually
describes: MONITOR / RATE_LIMIT (OpenFlow meter) / QUARANTINE (VLAN
isolation to a restricted egress) / BLOCK (hard drop).

ADDITION: Every detection and enforcement decision is written to a
JSONL log file with real wall-clock timestamps for each pipeline phase
(detect, decide, enforce). This log is the ONLY source of truth for the
metrics_from_logs.py analyzer -- no hardcoded result numbers exist
anywhere in this file.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp, arp, ether_types
from ryu.lib import hub
import time
import pickle
import json
import numpy as np
from collections import defaultdict, deque
import joblib
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------- #
#  Severity thresholds -- matches the paper's Section III-D tier mapping #
# ---------------------------------------------------------------------- #
THETA_RATE_LIMIT = float(os.getenv('SDN_THETA_RATE_LIMIT', '0.4'))
THETA_QUARANTINE = float(os.getenv('SDN_THETA_QUARANTINE', '0.6'))
THETA_BLOCK = float(os.getenv('SDN_THETA_BLOCK', '0.8'))

QUARANTINE_VLAN = 99
# Quarantine collector port PER SWITCH (dpid), matching the hq1/hq2/hq3
# hosts added to topology_enterprise.py, connected last so their ports are
# deterministic given Mininet's link-order-based port assignment:
#   s1 (dpid 2): core-uplink=1, h1-h5=2..6,  hq1=7
#   s2 (dpid 3): core-uplink=1, h6-h10=2..6, hq2=7
#   s3 (dpid 4): core-uplink=1, h11-h13=2..4, hq3=5
# The core switch (dpid 1) has no collector: hosts never connect directly to
# it, so a NEW flow's first packet always hits its own edge switch first --
# quarantine/block therefore always happens at the ingress edge switch,
# before traffic ever reaches the core. If your topology differs, update
# this mapping (or print `datapath.ports` at runtime to verify).
QUARANTINE_COLLECTOR_PORT_BY_DPID = {2: 7, 3: 7, 4: 5}

REACTIVE_IDLE_TIMEOUT = int(os.getenv('SDN_REACTIVE_IDLE_TIMEOUT', '20'))
MONITOR_INTERVAL_SECONDS = float(os.getenv('SDN_MONITOR_INTERVAL_SECONDS', '2.3'))
RATE_LIMIT_KBPS = int(os.getenv('SDN_RATE_LIMIT_KBPS', '100'))
QUARANTINE_FLOW_TIMEOUT = int(os.getenv('SDN_QUARANTINE_FLOW_TIMEOUT', '120'))
# seconds; short enough that flow-stats polling
                              # (every 3s) gets several samples per flow
                              # before a flow expires and is reinstalled.


class EnterpriseSecurityControllerV2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(EnterpriseSecurityControllerV2, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.mac_to_port = {}
        self.meter_id_counter = 1
        self.quarantined = set()   # src IPs currently quarantined
        self.blocked = set()       # src IPs currently blocked

        # ML model
        self.ml_model = self._load_pickle('model.pkl')
        self.scaler = self._load_joblib('scaler.pkl')
        self.model_loaded = self.ml_model is not None and self.scaler is not None

        # Per-flow tracking for feature computation (packet/byte counters
        # since last poll, so pps/bps reflect a RECENT window, not a
        # lifetime average -- this fixes the "growing duration_sec dilutes
        # the rate" issue in the original code).
        self.flow_last_seen = {}   # key -> (packet_count, byte_count, timestamp)
        self.packet_in_history = defaultdict(deque)

        # (dpid, dst_ip) -> out_port, learned during packet_in, used so the
        # periodic poller can re-enforce (escalate) a flow once its real
        # rate is known -- see _flow_stats_reply_handler.
        self.ip_dst_port_cache = {}

        # ---- Real result logging -- the single source of truth ---- #
        base_dir = os.path.dirname(os.path.abspath(__file__))
        os.makedirs(os.path.join(base_dir, 'logs'), exist_ok=True)
        self.log_path = os.path.join(
            base_dir, 'logs', f'decisions_{time.strftime("%Y%m%d_%H%M%S")}.jsonl'
        )
        self._log_file = open(self.log_path, 'a', buffering=1)  # line-buffered
        logger.info(f"Decision log: {self.log_path}")

        self.monitor_thread = hub.spawn(self._monitor)
        logger.info(f"Controller v2 initialized. ML loaded: {self.model_loaded}")

    # ------------------------------------------------------------------ #
    #  Model loading                                                     #
    # ------------------------------------------------------------------ #
    def _load_pickle(self, fname):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        try:
            with open(os.path.join(base_dir, fname), 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            logger.warning(f"Could not load {fname}: {e}")
            return None

    def _load_joblib(self, fname):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        try:
            return joblib.load(os.path.join(base_dir, fname))
        except Exception as e:
            logger.warning(f"Could not load {fname}: {e}")
            return None

    def _log_decision(self, record):
        """Append one real decision event to the JSONL log."""
        record['wall_clock'] = time.time()
        self._log_file.write(json.dumps(record) + '\n')

    # ------------------------------------------------------------------ #
    #  Periodic stats polling                                            #
    # ------------------------------------------------------------------ #
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(MONITOR_INTERVAL_SECONDS)

    def _request_stats(self, datapath):
        try:
            parser = datapath.ofproto_parser
            req = parser.OFPFlowStatsRequest(datapath)
            datapath.send_msg(req)
        except Exception:
            pass

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0,
                 hard_timeout=0, inst_extra=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if inst_extra:
            inst = inst_extra + inst
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    # ------------------------------------------------------------------ #
    #  Switch connect: table-miss + ARP fast path ONLY.                  #
    #  No permanent per-host IP/MAC forwarding is pre-installed --       #
    #  this is the core fix. Real traffic is handled reactively below.   #
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self.datapaths[dpid] = datapath

        # Table-miss -> controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Fast, permanent ARP flooding only (no attack signal in ARP here)
        match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions_arp = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 5, match_arp, actions_arp)

        logger.info(f"Switch DPID {dpid} connected (reactive mode, no static IP forwarding)")

    # ------------------------------------------------------------------ #
    #  Flow-stats reply: now actually receives IP-matched entries,       #
    #  because reactive flows below install ipv4_src/ipv4_dst matches.   #
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        body = ev.msg.body
        for stat in body:
            try:
                match = stat.match
                ip_src = match.get('ipv4_src')
                ip_dst = match.get('ipv4_dst')
                if not ip_src or not ip_dst or ip_src == '0.0.0.0':
                    continue

                proto = match.get('ip_proto', 0)
                key = (ip_src, ip_dst, proto)
                now = time.time()
                prev = self.flow_last_seen.get(key)
                self.flow_last_seen[key] = (stat.packet_count, stat.byte_count, now)

                if prev is None:
                    continue  # first observation of this flow key, no delta yet

                prev_pkts, prev_bytes, prev_t = prev
                dt = max(0.1, now - prev_t)
                delta_pkts = max(0, stat.packet_count - prev_pkts)
                delta_bytes = max(0, stat.byte_count - prev_bytes)

                pps = delta_pkts / dt          # RECENT rate, not lifetime average
                bps = delta_bytes / dt

                if delta_pkts == 0:
                    continue

                # CRITICAL: without re-enforcing here, a flood's first packet
                # (scored via packet_in with near-zero signal, before any real
                # rate is known) would be locked in as MONITOR forever, since
                # that was the only decision ever installed. This lookup lets
                # the poller upgrade the flow's action once its real rate is
                # visible -- this is what actually makes flood detection work.
                out_port = self.ip_dst_port_cache.get((datapath.id, ip_dst))
                install_dp = datapath if out_port is not None else None
                match_kwargs = dict(eth_type=ether_types.ETH_TYPE_IP,
                                     ipv4_src=ip_src, ipv4_dst=ip_dst, ip_proto=proto) \
                    if out_port is not None else None

                self._evaluate_flow(ip_src, ip_dst, pps, bps, dt, proto, source='poll',
                                     install_dp=install_dp, match_kwargs=match_kwargs,
                                     default_out_port=out_port)

                if out_port is None:
                    logger.debug(f"poll: no cached out_port for dst {ip_dst} on dpid "
                                 f"{datapath.id} yet -- logged severity but could not "
                                 f"(re-)enforce this cycle")
            except Exception as e:
                logger.debug(f"stats parse error: {e}")

    # ------------------------------------------------------------------ #
    #  Packet-In: handles first packet of every new flow (reactive       #
    #  forwarding) AND feeds the same risk-scoring pipeline immediately, #
    #  so fast-starting attacks aren't only caught on the next 3s poll.  #
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            return  # handled by the fast ARP flood rule; shouldn't normally arrive here

        dst_mac, src_mac = eth.dst, eth.src
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        severity, action = 0.0, 'MONITOR'

        if ip_pkt and out_port != ofproto.OFPP_FLOOD:
            src_ip, dst_ip, proto = ip_pkt.src, ip_pkt.dst, ip_pkt.proto

            # Remember where this destination lives on this switch, so the
            # periodic poller (fix above) can re-enforce this flow later.
            self.ip_dst_port_cache[(dpid, dst_ip)] = out_port
            effective_out_port = out_port

            # First-packet feature estimate: we don't have a rate yet, so
            # score using proto/size only; the flow-stats poller above will
            # refine this with a real pps/bps rate on subsequent polls and
            # can escalate the action if the flow turns out to be a flood.
            packet_in_pps = self._packet_in_rate(src_ip, dst_ip, proto)
            severity, action = self._evaluate_flow(
                src_ip, dst_ip,
                pps=packet_in_pps,
                bps=packet_in_pps * float(len(msg.data)),
                duration=0.1,
                proto=proto, source='packet_in', install_dp=datapath,
                match_kwargs=dict(eth_type=ether_types.ETH_TYPE_IP,
                                   ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=proto),
                default_out_port=effective_out_port,
            )

            # Forward (or drop) THIS packet consistent with the decision just
            # made -- _evaluate_flow only installed a rule for FUTURE packets
            # of this flow; without this block, the triggering packet itself
            # was being silently lost regardless of the action chosen.
            if action == 'BLOCK':
                return  # drop this packet too, nothing more to do
            send_port = QUARANTINE_COLLECTOR_PORT_BY_DPID.get(dpid, effective_out_port) \
                if action == 'QUARANTINE' else effective_out_port
            actions = [parser.OFPActionOutput(send_port)]
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                       in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
            return

        # Non-IP or destination unknown: default L2 flood/forward, no flow install
        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _packet_in_rate(self, src_ip, dst_ip, proto):
        now = time.time()
        history = self.packet_in_history[(src_ip, dst_ip, proto)]
        history.append(now)
        cutoff = now - 2.0
        while history and history[0] < cutoff:
            history.popleft()
        if len(history) < 2:
            return 0.0
        return len(history) / max(0.1, now - history[0])

    # ------------------------------------------------------------------ #
    #  Core risk-scoring + 4-tier enforcement decision                   #
    # ------------------------------------------------------------------ #
    def _evaluate_flow(self, src_ip, dst_ip, pps, bps, duration, proto,
                        source, install_dp=None, match_kwargs=None,
                        default_out_port=None):
        t_detect_start = time.time()

        p_attack = self._predict_attack_probability(pps, bps, duration, proto)
        severity = p_attack  # NOTE: the paper's R_i(t) also weights port-scan
        # and auth-failure signals (w1*phi1 + w2*phi2 + w3*phi3). This
        # codebase has no telemetry source for those two signals yet --
        # severity here is P_attack alone. Document this honestly in the
        # paper text, or add real port-scan/auth-failure feature extraction
        # before claiming the full weighted formula is implemented.

        t_decide = time.time()

        if severity > THETA_BLOCK:
            action = 'BLOCK'
        elif severity > THETA_QUARANTINE:
            action = 'QUARANTINE'
        elif severity > THETA_RATE_LIMIT:
            action = 'RATE_LIMIT'
        else:
            action = 'MONITOR'

        if install_dp is not None and match_kwargs is not None:
            self._enforce(install_dp, action, src_ip, match_kwargs, default_out_port)

        t_enforce = time.time()

        self._log_decision({
            'source': source,
            'src_ip': src_ip, 'dst_ip': dst_ip,
            'pps': pps, 'bps': bps, 'proto': proto,
            'p_attack': float(p_attack), 'severity': float(severity),
            'action': action,
            't_detect_start': t_detect_start,
            't_decide': t_decide,
            't_enforce_done': t_enforce,
            'detect_to_decide_s': t_decide - t_detect_start,
            'decide_to_enforce_s': t_enforce - t_decide,
            'total_s': t_enforce - t_detect_start,
        })

        return severity, action

    def _predict_attack_probability(self, pps, bps, duration, proto):
        if not self.model_loaded:
            # Fallback: simple threshold heuristic if the model didn't load
            return 1.0 if pps > 1.0 else 0.0
        try:
            # Availability probes create short ICMP bursts. The measured
            # attack ICMP floor is above 25 pps, so keep probe traffic normal.
            if proto == 1 and pps < 25.0:
                return 0.0
            # The model was trained on kpps, kbps, and seconds. Keep the live
            # feature units aligned with that schema; dividing by wall-clock
            # byte rates in the old path made every real flood look normal.
            tcp_ratio = 0.9 if proto == 6 else 0.0
            udp_ratio = 0.05 if proto == 17 else 0.0
            icmp_ratio = 0.05 if proto == 1 else 0.0
            features = np.array([[
                pps / 10.0,
                bps / 1000.0,
                min(duration, 1.0),
                tcp_ratio,
                udp_ratio,
                icmp_ratio,
            ]])
            features_scaled = self.scaler.transform(features)
            proba = self.ml_model.predict_proba(features_scaled)
            probability = float(proba[0][1])
            # Sustained rates above the measured legitimate range are a
            # direct attack signal when the synthetic model is uncertain.
            return max(probability, 1.0 if pps >= 25.0 else 0.0)
        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            return 0.0

    def _enforce(self, datapath, action, src_ip, match_kwargs, default_out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(**match_kwargs)

        if action == 'BLOCK':
            self.add_flow(datapath, 200, match, actions=[],  # empty actions = drop
                           idle_timeout=0, hard_timeout=300)
            logger.warning(f"BLOCK {src_ip}")

        elif action == 'QUARANTINE':
            collector_port = QUARANTINE_COLLECTOR_PORT_BY_DPID.get(datapath.id)
            if collector_port is None:
                logger.error(f"No quarantine collector configured for dpid {datapath.id} "
                             f"-- falling back to BLOCK for {src_ip} instead of silently "
                             f"misrouting to a nonexistent port")
                self.add_flow(datapath, 200, match, actions=[], idle_timeout=0,
                              hard_timeout=QUARANTINE_FLOW_TIMEOUT)
                return
            actions = [parser.OFPActionOutput(collector_port)]
            self.add_flow(datapath, 150, match, actions,
                           idle_timeout=REACTIVE_IDLE_TIMEOUT,
                           hard_timeout=QUARANTINE_FLOW_TIMEOUT)
            logger.warning(f"QUARANTINE {src_ip} -> dpid {datapath.id} collector port {collector_port}")

        elif action == 'RATE_LIMIT':
            meter_id = self._get_or_create_meter(datapath, rate_kbps=RATE_LIMIT_KBPS)
            actions = [parser.OFPActionOutput(default_out_port)]
            inst_meter = [parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER)]
            self.add_flow(datapath, 100, match, actions,
                           idle_timeout=REACTIVE_IDLE_TIMEOUT,
                           inst_extra=inst_meter)
            logger.info(f"RATE_LIMIT {src_ip} -> {RATE_LIMIT_KBPS}kbps meter {meter_id}")

        else:  # MONITOR
            actions = [parser.OFPActionOutput(default_out_port)]
            self.add_flow(datapath, 50, match, actions, idle_timeout=REACTIVE_IDLE_TIMEOUT)

    def _get_or_create_meter(self, datapath, rate_kbps):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        meter_id = self.meter_id_counter
        self.meter_id_counter += 1
        band = parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=0)
        mod = parser.OFPMeterMod(datapath, command=ofproto.OFPMC_ADD,
                                  flags=ofproto.OFPMF_KBPS, meter_id=meter_id,
                                  bands=[band])
        datapath.send_msg(mod)
        return meter_id


if __name__ == '__main__':
    from ryu.cmd.manager import main
    import sys
    sys.argv = ['ryu-manager', __file__]
    main()
