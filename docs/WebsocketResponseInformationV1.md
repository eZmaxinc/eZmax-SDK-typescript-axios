# WebsocketResponseInformationV1

Response for Websocket Information V1

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**eWebsocketMessagetype** | **string** | The Type of message | [default to undefined]
**sWebsocketChannel** | **string** | The Channel on which to route the websocket message | [default to undefined]
**mPayload** | [**WebsocketResponseInformationV1MPayload**](WebsocketResponseInformationV1MPayload.md) |  | [default to undefined]

## Example

```typescript
import { WebsocketResponseInformationV1 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: WebsocketResponseInformationV1 = {
    eWebsocketMessagetype,
    sWebsocketChannel,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
