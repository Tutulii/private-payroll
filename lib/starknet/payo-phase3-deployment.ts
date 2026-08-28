export const PAYO_PHASE3_MAINNET_DEPLOYMENT = Object.freeze({
  adminAddress: "0x0126a7a572cf8935d069af937e9f7b27a24949e271e1fbccfe4de0c0d8dc8ea9",
  sealAddress: "0x603c607bf001e279365fd141901ba09b95f72f5a72506742b30f6db32c36ac7",
  sealClassHash: "0x1500b1e66ef8c1528f5ea301cbb0420b28a19742d927c5d595ce567b0266148",
  policyRegistryAddress: "0x34701f573096b7bab0e5678e1ed2f17a87c8d56eb5f4d70bcf2197bab8e4477",
  obligationRegistryAddress: "0x44b22f1a17d2710c2f51ed0b37b8b0ff8435262d3c8c0f2f17be07c84ac23b5",
  profiles: Object.freeze([
    Object.freeze({
      name: "Advanced payroll",
      mode: 0,
      proofVersion: 2,
      bundleAddress: "0xeba326f15f73968026bd12007220d88104fdcb322a56ad8c69fbe8a5350e18",
      bundleClassHash: "0x451e59b2f2e454a5a53914ca317069d84faf504498e1d56609a78fb626da2bc",
    }),
    Object.freeze({
      name: "Private wage claim",
      mode: 2,
      proofVersion: 3,
      bundleAddress: "0x7825f82260d4852279e54930ccac1afecf3364c87bf58216e8f4a65e73f414",
      bundleClassHash: "0x451e59b2f2e454a5a53914ca317069d84faf504498e1d56609a78fb626da2bc",
    }),
    Object.freeze({
      name: "Private remediation",
      mode: 3,
      proofVersion: 4,
      bundleAddress: "0x37673733211e16d2ea42ba85eb5eb6bf9913424a96136145834cd9d1d834b71",
      bundleClassHash: "0x451e59b2f2e454a5a53914ca317069d84faf504498e1d56609a78fb626da2bc",
    }),
  ] as const),
});

export type PayoPhase3Profile = typeof PAYO_PHASE3_MAINNET_DEPLOYMENT.profiles[number];
