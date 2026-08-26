export const PAYO_PHASE3_MAINNET_DEPLOYMENT = Object.freeze({
  adminAddress: "0x038c1d4e372a3cdf605a0c06d944b046c7f4d7923922001f9366b5d000aa3871",
  sealAddress: "0x2930f94183c60d86b9e35486c46c0f73bec8cd532e3fadc8c661cf9ec0ebd99",
  sealClassHash: "0x1500b1e66ef8c1528f5ea301cbb0420b28a19742d927c5d595ce567b0266148",
  policyRegistryAddress: "0x4e5309dc9662bf8e136c1d626c1410ea07f74e743a0972c1e253b08ece46aad",
  obligationRegistryAddress: "0x21a91368561d32c91a861412ec6823a21cc2b64ab10110f575bf57709b7880c",
  profiles: Object.freeze([
    Object.freeze({
      name: "Advanced payroll",
      mode: 0,
      proofVersion: 2,
      bundleAddress: "0x26b27ef2b9cbfc11782689b3da77a0d42c64050277d77ccffe22907ed64c07a",
      bundleClassHash: "0x4aa085123d4a93f531b112e4928216b58c583373b28db9da3e4d57f97b8259f",
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
