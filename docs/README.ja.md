# 導入手順（日本語）

このツールは、SSH・HTTP・Docker・systemd・ディスクの状況を要約し、SMTPでメール送信します。各サーバーのroot権限で利用します。公開するGitリポジトリには実環境の固有情報を保存しません。

## インストール

```bash
sudo bash install.sh
sudo server-security-setup --init
sudo server-security-setup --validate
sudo server-security-report --test-email
sudo server-security-report --dry-run
sudo systemctl enable --now security-report-daily.timer security-report-alert.timer
```

`--init` はSMTP情報、Gmailアプリパスワード、送信先、コンテナ、systemdサービス、ログファイルのパターン、検出条件、閾値、例外、重大度を対話式で設定します。パスワードは画面に表示されません。設定を更新するときは `sudo server-security-setup --configure` を実行します。

保存先は `/etc/server-security-report/` で、設定と秘密情報はroot専用の権限にします。Python本体を編集する必要はありません。メールの送信テストは `sudo server-security-report --test-email` です。

## GitHub公開前の確認

- 実際のメールアドレス、ホスト名、組織名、研究名、サービス固有の名称、IPアドレス、ログの抜粋をソースやREADMEに含めない。
- 既存の秘密を含むGit履歴は流用せず、新規リポジトリを作成する。
- `.gitignore` に頼らず、`git status` とステージング済みファイルを確認する。
- `python3 privacy_check.py` を実行し、人手でも機密情報を点検する。
- GitHubユーザー名・メールアドレス・コミット作成者・公開組織の情報から、投稿者が特定される可能性を考慮する。

テストは `python3 -m unittest discover -s tests -v`、実行ログは `journalctl -u security-report-daily.service` などで確認できます。
