import config from "../public/icons/config.json";

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

  const BASE_URL = "https://lunari-server.vercel.app";

  // 🔥 연도 무시 특별한 날
  const specialDays = ["1-1", "12-25"];

  const count = config[element];

  if (!count) {
    return res.status(400).json({ error: "Invalid element" });
  }

  // 🔥 특별날 처리
  if (specialDays.includes(monthDay)) {
    // special 폴더 안에도 숫자형 파일로 관리한다고 가정
    const specialCount = 3; // 예: special 3개 있다면
    const specialIndex = (seed % specialCount) + 1;

    return res.status(200).json({
      element,
      type: "special",
      imageUrl: `${BASE_URL}/icons/${element}/special${specialIndex}.png`
    });
  }

  // 🔥 일반 이미지 순환
  const index = (seed % count) + 1;

  return res.status(200).json({
    element,
    type: "normal",
    imageUrl: `${BASE_URL}/icons/${element}/${index}.png`
  });
}
