# 部署说明（GitHub Pages / Cloudflare Pages）

当前线上地址（WorkBuddy 托管，已验证可访问）：

```
https://xuanyin.app.workbuddy.host/?sharecode=UZEKCLJBNL
```

本目录本身就是一个可直接部署的静态站点，入口 `index.html`，无需构建、无依赖。

## 一、GitHub Pages

1. 在 GitHub 网页新建仓库，例如 `xuanyin`，可见性选 Public，不要勾选初始化 README。
2. 在本目录执行（把 `<user>` 换成你的 GitHub 用户名）：

```bash
git remote add origin git@github.com:<user>/xuanyin.git
git push -u origin main --tags
```

3. 仓库 Settings → Pages → Build and deployment → Source 选 **GitHub Actions**。
   目录里已带 `.github/workflows/pages.yml`，推送后自动部署；也可选 “Deploy from a branch” → `main` → `/ (root)`，`.nojekyll` 已放好。
4. 地址为 `https://<user>.github.io/xuanyin/`。

注意：GitHub 与 `github.io` 在国内访问不稳定，评委打不开时请以提交文档第五章为准。

## 二、Cloudflare Pages

方式 A（网页，推荐）：Dashboard → Workers & Pages → Create → Pages → Connect to Git →
选择上面的仓库；Framework preset 选 None，Build command 留空，Build output directory 填 `/`。

方式 B（命令行）：

```bash
npx wrangler@latest pages deploy . --project-name xuanyin
```

得到 `https://xuanyin.pages.dev`。`*.pages.dev` 在国内部分运营商、部分时段会被阻断；
有条件时绑定自定义域名（域名 NS 托管到 Cloudflare），可达性会明显改善。

## 三、更新与一致性

1. 任何源文件改动后，重新生成 `SHA256SUMS.txt`，并同步更新提交文档 4.2 的校验表。
2. 重新打 tag：`git tag -a v1.1.1 -m "v1.1.1"`，重新部署。
3. 线上文件必须与文档第五章逐字一致，否则评委会认为线上线下两套内容。

## 四、不要提交的文件

`.wbapp_*.genie`、`.DS_Store`、`Thumbs.db` 已在 `.gitignore` 中排除；不要把个人账号信息写进 README。
