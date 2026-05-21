<?php

namespace LittleSkin\YggdrasilConnect\OIDC;

class OIDCException extends \Exception
{
    public string $error;
    public string $errorDescription;
    public ?string $state;

    public function __construct(string $error, string $errorDescription, ?string $state = null)
    {
        $this->error = $error;
        $this->errorDescription = $errorDescription;
        $this->state = $state;
        parent::__construct($errorDescription);
    }

    public function toArray(): array
    {
        $result = [
            'error' => $this->error,
            'error_description' => $this->errorDescription,
        ];

        if ($this->state !== null) {
            $result['state'] = $this->state;
        }

        return $result;
    }
}
