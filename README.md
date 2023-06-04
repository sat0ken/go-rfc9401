# go-rfc9401

RFC9401をGoで実装したリポジトリです。  
動かしたい場合は`example`フォルダ内のプログラムをsudoで実行してください。

プログラムを実行する前に、以下のコマンドでRSTパケットをDROPするようにしてください。

```shell
sudo iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -p tcp --tcp-flags RST RST -j DROP
```

https://tex2e.github.io/rfc-translater/html/rfc9401.html