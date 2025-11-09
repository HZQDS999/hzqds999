const Imap = require('node-imap');
const simpleParser = require("mailparser").simpleParser;

// 生成邮件HTML的通用函数
function generateEmailHtml(emailData) {
  // 转义特殊字符，防止XSS攻击
  const escapeHtml = (str) => str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

  const { send, subject, text, html: emailHtml, date } = emailData;
  const escapedText = escapeHtml(text || '');
  const escapedHtml = emailHtml || `<p>${escapedText.replace(/\n/g, '<br>')}</p>`;

  return `
    <!DOCTYPE html>
    <html lang="zh-CN">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${escapeHtml(subject || '邮件内容')}</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background: #f5f5f5; }
          .email-container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          .email-header { margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid #eee; }
          .email-title { margin: 0 0 15px; color: #2d3748; }
          .email-meta { color: #4a5568; font-size: 0.9em; }
          .email-meta span { display: block; margin-bottom: 5px; }
          .email-content { color: #1a202c; }
          .email-text { white-space: pre-line; }
        </style>
      </head>
      <body>
        <div class="email-container">
          <div class="email-header">
            <h1 class="email-title">${escapeHtml(subject || '无主题')}</h1>
            <div class="email-meta">
              <span><strong>发件人：</strong>${escapeHtml(send || '未知')}</span>
              <span><strong>日期：</strong>${new Date(date).toLocaleString() || '未知'}</span>
            </div>
          </div>
          <div class="email-content">
            ${escapedHtml}
          </div>
        </div>
      </body>
    </html>
  `;
}

async function get_access_token(refresh_token, client_id) {
    const response = await fetch('https://login.microsoftonline.com/consumers/oauth2/v2.0/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            'client_id': client_id,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        }).toString()
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP error! status: ${response.status}, response: ${errorText}`);
    }

    const responseText = await response.text();

    try {
        const data = JSON.parse(responseText);
        return data.access_token;
    } catch (parseError) {
        throw new Error(`Failed to parse JSON: ${parseError.message}, response: ${responseText}`);
    }
}

const generateAuthString = (user, accessToken) => {
    const authString = `user=${user}\x01auth=Bearer ${accessToken}\x01\x01`;
    return Buffer.from(authString).toString('base64');
}

async function graph_api(refresh_token, client_id) {
    const response = await fetch('https://login.microsoftonline.com/consumers/oauth2/v2.0/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            'client_id': client_id,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'scope': 'https://graph.microsoft.com/.default'
        }).toString()
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP error! status: ${response.status}, response: ${errorText}`);
    }

    const responseText = await response.text();

    try {
        const data = JSON.parse(responseText);

        if (data.scope.indexOf('https://graph.microsoft.com/Mail.ReadWrite') != -1) {
            return {
                access_token: data.access_token,
                status: true
            }
        }

        return {
            access_token: data.access_token,
            status: false
        }
    } catch (parseError) {
        throw new Error(`Failed to parse JSON: ${parseError.message}, response: ${responseText}`);
    }
}

// 修改get_emails函数，支持返回原始数据
async function get_emails(access_token, mailbox, returnRaw = false) {
    if (!access_token) {
        console.log("Failed to obtain access token'");
        return;
    }

    try {
        const response = await fetch(`https://graph.microsoft.com/v1.0/me/mailFolders/${mailbox}/messages?$top=1&$orderby=receivedDateTime desc`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                "Authorization": `Bearer ${access_token}`
            },
        });

        if (!response.ok) {
            const errorText = await response.text();
            return;
        }

        const responseData = await response.json();
        const emails = responseData.value;

        const response_emails = emails.map(item => ({
            send: item['from']['emailAddress']['address'],
            subject: item['subject'],
            text: item['bodyPreview'],
            html: item['body']['content'],
            date: item['createdDateTime'],
        }));

        // 根据参数决定返回格式
        return returnRaw ? response_emails[0] : response_emails;

    } catch (error) {
        console.error('Error fetching emails:', error);
        return;
    }
}

module.exports = async (req, res) => {
    const { password } = req.method === 'GET' ? req.query : req.body;
    const expectedPassword = process.env.PASSWORD;

    if (password !== expectedPassword && expectedPassword) {
        return res.status(401).json({
            error: 'Authentication failed. Please provide valid credentials.'
        });
    }

    const params = req.method === 'GET' ? req.query : req.body;
    let { refresh_token, client_id, email, mailbox, response_type = 'json' } = params;

    if (!refresh_token || !client_id || !email || !mailbox) {
        return res.status(400).json({ error: 'Missing required parameters' });
    }

    try {
        console.log("检查是否使用Graph API");
        const graph_api_result = await graph_api(refresh_token, client_id);

        if (graph_api_result.status) {
            console.log("使用Graph API获取邮件");
            
            // 统一邮箱文件夹格式
            if (mailbox !== "INBOX" && mailbox !== "Junk") {
                mailbox = "inbox";
            }
            if (mailbox === 'INBOX') mailbox = 'inbox';
            if (mailbox === 'Junk') mailbox = 'junkemail';

            // 根据响应类型处理
            const emailData = await get_emails(graph_api_result.access_token, mailbox, true);
            if (response_type === 'html') {
                const htmlResponse = generateEmailHtml(emailData);
                res.status(200).send(htmlResponse);
            } else {
                res.status(200).json([emailData]);
            }
            return;
        }

        // 否则使用IMAP协议
        console.log("使用IMAP获取邮件");
        const access_token = await get_access_token(refresh_token, client_id);
        const authString = generateAuthString(email, access_token);

        const imap = new Imap({
            user: email,
            xoauth2: authString,
            host: 'outlook.office365.com',
            port: 993,
            tls: true,
            tlsOptions: {
                rejectUnauthorized: false
            }
        });

        imap.once("ready", async () => {
            try {
                await new Promise((resolve, reject) => {
                    imap.openBox(mailbox, true, (err, box) => {
                        if (err) return reject(err);
                        resolve(box);
                    });
                });

                const results = await new Promise((resolve, reject) => {
                    imap.search(["ALL"], (err, results) => {
                        if (err) return reject(err);
                        const latestMail = results.slice(-1); // 获取最新一封
                        resolve(latestMail);
                    });
                });

                const f = imap.fetch(results, { bodies: "" });

                f.on("message", (msg, seqno) => {
                    msg.on("body", (stream, info) => {
                        simpleParser(stream, (err, mail) => {
                            if (err) throw err;
                            const responseData = {
                                send: mail.from.text,
                                subject: mail.subject,
                                text: mail.text,
                                html: mail.html,
                                date: mail.date,
                            };

                            // 处理响应类型
                            if (response_type === 'json') {
                                res.status(200).json(responseData);
                            } else if (response_type === 'html') {
                                const htmlResponse = generateEmailHtml(responseData);
                                res.status(200).send(htmlResponse);
                            } else {
                                res.status(400).json({ error: 'Invalid response_type. Use "json" or "html".' });
                            }
                        });
                    });
                });

                f.once("end", () => {
                    imap.end();
                });
            } catch (err) {
                imap.end();
                res.status(500).json({ error: err.message });
            }
        });

        imap.once('error', (err) => {
            console.error('IMAP error:', err);
            res.status(500).json({ error: err.message });
        });

        imap.connect();

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: error.message });
    }
};
