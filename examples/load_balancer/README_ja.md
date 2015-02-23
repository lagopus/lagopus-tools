# ロードバランサ

特定のIPアドレス(10.0.0.100)宛のパケットを複数のサーバに分散させる。  
対話的にサーバの追加、削除、確認が行える。

**Note**:
- このアプリケーションはLagopusのポート1から入ったパケットをポート2以降に接続されたサーバに分散させる。
- 振り分けはラウンドロビン方式(順番に振り分ける)。
- サーバ間での通信はサポートしていない。

## ロードバランサの使い方

ロードバランサのアプリケーションを実行するためには、Ryuがインストールされている必要がある。
インストールされていない場合は、[README](./path/to/ansible_readme)に従って、OpenFlowスイッチ(Lagopus)とRyuをインストールする。

### ロードバランサの実行

`ryu-manager`からロードバランサを起動することができる。

```
$ ryu-manager load_balancer.py
```

### サーバの追加、削除

アプリケーションが起動すると、端末上に`input > `と表示される。
ここにコマンドの入力してサーバの追加と削除を行う。

サーバ(IPアドレス=10.0.0.2, MACアドレス=aa:aa:aa:aa:aa:aa, Lagopusの出力ポート=2)を追加する。

```
input > add 10.0.0.2 aa:aa:aa:aa:aa:aa 2
```

サーバの一覧を表示する。

```
       IPv4       |        MAC        | OUT_PORT
------------------+-------------------+----------
     10.0.0.2     | aa:aa:aa:aa:aa:aa |    2
```

サーバを削除する。

```
input > del 10.0.0.2 aa:aa:aa:aa:aa:aa 2
```

サーバが削除されていることを確認する。

```
input > show
Servers not found
```

### コマンド一覧

```
add ip mac out_port: サーバを追加する
del ip mac out_port: サーバを削除する
show          : 全てのサーバを表形式で出力する
dump          : 全てのFlow Ruleをjson形式で出力する

ip        : サーバのIPアドレス
mac       : サーバのMACアドレス
out_port  : サーバと接続されているLagopusのポート番号
```

**Note**:
- addコマンドを実行した時にFlow Ruleが追加されるわけではない(10.0.0.100への接続があった時に追加される)。
- delコマンドでは指定されたサーバへの今後割り当てが行われなくなるだけで、Flow Ruleの削除は行われない。
- 20秒間通信が行われなかったFlow Ruleは自動で削除される。



