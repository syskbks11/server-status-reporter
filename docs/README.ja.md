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

`--init` は簡易設定です。SMTPの送信元アドレス、送信先（複数指定可能）、アプリパスワード（非表示・確認入力）のみを入力し、その他はデフォルトを採用します。最後に保存を確認します。SMTPホスト・ポートは初期値として `smtp.gmail.com:587`（STARTTLS）を使用します。

その後、必要な項目だけ変更するには `sudo server-security-setup --configure` を実行します。最初にカテゴリを番号で選び、次に変更したい項目を番号で選択します。ほかの設定を次々に質問されることはありません。サブメニューの`0`で戻り、メインメニューの`8`で検証・保存、`0`で変更を破棄します。設定内容はGitHubに保存されません。

初期状態では監視対象コンテナ・サービスの必須リスト、HTTPアクセスログのパス、信頼済みネットワークは空です。必要に応じて設定してください。Dockerの公開ポート許可リストが空の場合は、公開状況を日報に記載しますが、リスト外公開ポートの緊急通知は行いません。許可リストを設定した時点から検知を有効にします。

保存先は `/etc/server-security-report/` で、設定と秘密情報はroot専用の権限にします。Python本体を編集する必要はありません。メールの送信テストは `sudo server-security-report --test-email` です。

## GitHub公開前の確認

- 実際のメールアドレス、ホスト名、組織名、研究名、サービス固有の名称、IPアドレス、ログの抜粋をソースやREADMEに含めない。
- 既存の秘密を含むGit履歴は流用せず、新規リポジトリを作成する。
- `.gitignore` に頼らず、`git status` とステージング済みファイルを確認する。
- `python3 privacy_check.py` を実行し、人手でも機密情報を点検する。
- GitHubユーザー名・メールアドレス・コミット作成者・公開組織の情報から、投稿者が特定される可能性を考慮する。

テストは `python3 -m unittest discover -s tests -v`、実行ログは `journalctl -u security-report-daily.service` などで確認できます。

## 緊急通知・日報のルール（v4）

通常のSSH認証失敗とHTTPの不審アクセスは日報に集計し、原則として緊急メールは送信しません。緊急メールは、信頼済みネットワーク以外からのrootログイン、設定した条件を満たすSSH攻撃の急増、重要コンテナやsystemdサービスの異常、ディスク使用率の危険域到達などに限定します。個別の監視対象・通知条件は各サーバーで設定してください。

継続中の異常は`/var/lib/server-security-report/state.json`で管理します。15分ごとの監視で同じ異常が続いていても再送せず、翌日以降の日報には毎日掲載します。日報に同じ異常がすでに含まれる場合は重複して掲載しません。初回検知時刻も表示します。

異常の解消時は通常メールを送信せず、対話式設定の`notify_on_recovery`を有効にした場合だけ復旧通知を送信します。監視失敗などにより復旧が検証できない場合は、既存の異常状態を維持します。

**通知条件・閾値の保存先は1つのファイルです。** `/etc/server-security-report/config.json`内の`alert_policy`にまとまっています。rootのみ読み取り可能なためGitHubには含まれません。対話式CUIで設定するには以下を実行し、**4) Emergency notification policy**を選択します。

```bash
sudo server-security-setup --configure
sudo server-security-setup --validate
sudo server-security-report --mode alert --dry-run
```

`ssh_spike_trigger_count`と`ssh_spike_recovery_count`は15分あたりの失敗件数を基準とする発生・解除閾値です。`ssh_spike_increase_factor`は直前の監視区間に対する倍率です。`disk_critical_percent`と`disk_recovery_percent`はディスクの危険域到達・解除の基準値です。発生閾値と解除閾値に差を設けることで、境界付近での通知の繰り返しを防ぎます。

既存のv3から更新する場合、保存済みSMTP設定は維持されます。v4の緊急通知条件には初期値が適用されるため、定期監視を有効にする前にメニュー4で確認してください。以前の状態ファイルからは通知の継続状態を引き継がないので、初回の監視時に既存の異常について1回通知が発生する可能性があります。
