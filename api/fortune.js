export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  try {
    const { engineResult } = req.body;

    // =========================
    // 1️⃣ 전문가 해석 생성
    // =========================
    const expertResponse = await fetch(
      "https://api.openai.com/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`,
        },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          temperature: 0.65,
          response_format: { type: "json_object" },
          messages: [
            {
              role: "system",
              content:
                "너는 사주 명리 전문가다. 이미 계산된 사주 구조를 기반으로 전문적인 해석 리포트를 작성한다. 반드시 JSON만 출력한다.",
            },
            {
              role: "user",
              content: `
반드시 JSON만 출력한다.

[사주 구조]
${JSON.stringify(engineResult)}

출력 JSON 구조
{
  "종합운": { "analysis": "", "flow": { "초년": "", "중년": "", "말년": "" }},
  "재물운": { "analysis": "", "flow": { "초년": "", "중년": "", "말년": "" }},
  "연애운": { "analysis": "", "flow": { "초년": "", "중년": "", "말년": "" }},
  "학업운": { "analysis": "", "flow": { "초년": "", "중년": "", "말년": "" }},
  "직업운": { "analysis": "", "flow": { "초년": "", "중년": "", "말년": "" }},
  "대운": { "summary": "", "detail": ["", "", "", ""] },
  "연간운": { "summary": "", "detail": ["", "", ""] },
  "분기운": { "봄": "", "여름": "", "가을": "", "겨울": "" },
  "월간운": { "summary": "", "detail": ["", "", ""] }
}
`,
            },
          ],
        }),
      }
    );

    const expertRaw = await expertResponse.json();
    const expert = JSON.parse(
      expertRaw.choices[0].message.content
    );

    // =========================
    // 2️⃣ 쉬운말 요약 생성
    // =========================
    const easyResponse = await fetch(
      "https://api.openai.com/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`,
        },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          temperature: 0.6,
          response_format: { type: "json_object" },
          messages: [
            {
              role: "system",
              content:
                "너는 사주 전문가의 설명을 일반인이 이해하기 쉽게 요약해주는 해설가다. 반드시 JSON만 출력한다. 모든 문장은 부드러운 반말이다. 사주 용어는 최대한 쓰지 않는다.",
            },
            {
              role: "user",
              content: `
반드시 JSON만 출력한다.

[전문가 해석]
${JSON.stringify(expert)}

출력 JSON 구조
{
  "종합운": "",
  "재물운": "",
  "연애운": "",
  "학업운": "",
  "직업운": ""
}
`,
            },
          ],
        }),
      }
    );

    const easyRaw = await easyResponse.json();
    const easy = JSON.parse(
      easyRaw.choices[0].message.content
    );

    // =========================
    // 최종 반환
    // =========================
    return res.status(200).json({
      engine: engineResult,
      expert,
      easy,
    });
  } catch (error) {
    return res.status(500).json({
      error: "SERVER_ERROR",
      detail: error.message,
    });
  }
}
