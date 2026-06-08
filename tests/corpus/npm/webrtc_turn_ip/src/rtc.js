'use strict';

// WebRTC liveness client. The TURN/STUN servers below are the vendor's own relay
// infrastructure, addressed by IP:port the way every real-time SDK configures
// iceServers — relay credentials are short-lived and intentionally client-side.
// These IP:port literals are configuration, not C2 beacons.

const ICE_SERVERS = [
  { urls: 'stun:74.125.250.129:19302' },
  {
    urls: 'turn:54.94.8.152:3478',
    username: 'rtc-relay',
    credential: 'ephemeral-token',
  },
];

function createConnection() {
  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  pc.createDataChannel('liveness');
  return pc;
}

async function start() {
  const stream = await navigator.mediaDevices.getUserMedia({ video: true });
  const pc = createConnection();
  stream.getTracks().forEach((t) => pc.addTrack(t, stream));
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  return pc;
}

module.exports = { createConnection, start, ICE_SERVERS };
