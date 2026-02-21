export default function handler(req, res) {
  const element = req.query.element || "wood";

  const today = new Date();
  const month = today.getMonth() + 1;
  const day = today.getDate();
  const monthDay = `${month}-${day}`;

  // 🔥 날짜 기반 시드 (연도 포함)
  const seed = parseInt(
    `${today.getFullYear()}${month}${day}`
  );

  // 🔥 특별한 날 (연도 무시)
  const specialDays = ["1-1", "12-25"];

  // 🔥 이미지 풀 (이름 지정 안함)
  const imagePool = {
    wood: {
      normal: [
        "/icons/wood/1.png",
        "/icons/wood/2.png",
        "/icons/wood/3.png",
        "/icons/wood/4.png"
      ],
      special: [
        "/icons/wood/special1.png",
        "/icons/wood/special2.png"
      ]
    },
    fire: {
      normal: ["/icons/fire/1.png"],
      special: []
    },
    earth: {
      normal: ["/icons/earth/1.png"],
      special: []
    },
    metal: {
      normal: ["/icons/metal/1.png"],
      special: []
    },
    water: {
      normal: ["/icons/water/1.png"],
      special: []
    }
  };

  const elementData = imagePool[element];

  if (!elementData) {
    return res.status(400).json({ error: "Invalid element" });
  }

  // 🔥 특별날이면 special 풀 사용
  if (specialDays.includes(monthDay) && elementData.special.length > 0) {
    const index = seed % elementData.special.length;
    return res.status(200).json({
      element,
      type: "special",
      imageUrl: elementData.special[index]
    });
  }

  // 🔥 일반 순환 (중복 없이 순환)
  const index = seed % elementData.normal.length;

  return res.status(200).json({
    element,
    type: "normal",
    imageUrl: elementData.normal[index]
  });
}
