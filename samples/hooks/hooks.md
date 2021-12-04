```json
[
  {
    "id": "deploy-mywebsite",
    "execute-command": "/usr/share/hooks/mywebsite/deploy.sh",
    "command-working-directory": "/var/www/mywebsite/app/",
    "pass-arguments-to-command":
    [
      {
        "source": "payload",
        "name": "head_commit.id"
      },
      {
        "source": "payload",
        "name": "mywebsite"
      },
      {
        "source": "payload",
        "name": "social@mywebsite.com"
      }
    ],
    "response-message": "Déploiement…",
    "trigger-rule":
    {
      "and":
      [
        {
          "match":
          {
            "type": "payload-hash-sha1",
            "secret": "SECRET_PHRASE",
            "parameter":
            {
              "source": "header",
              "name": "X-Hub-Signature"
            }
          }
        },
        {
          "match":
          {
            "type": "value",
            "value": "refs/heads/main",
            "parameter":
            {
              "source": "payload",
              "name": "ref"
            }
          }
        }
      ]
    }
  }
]
```