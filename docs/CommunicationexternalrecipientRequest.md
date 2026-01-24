# CommunicationexternalrecipientRequest

A Communicationexternalrecipient Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiCommunicationexternalrecipientID** | **number** | The unique ID of the Communicationexternalrecipient | [optional] [default to undefined]
**sEmailAddress** | **string** | The email address. | [optional] [default to undefined]
**sPhoneE164** | **string** | A phone number in E.164 Format | [optional] [default to undefined]
**eCommunicationexternalrecipientType** | [**FieldECommunicationexternalrecipientType**](FieldECommunicationexternalrecipientType.md) |  | [optional] [default to undefined]
**sCommunicationexternalrecipientName** | **string** | The name of the Communicationexternalrecipient | [optional] [default to undefined]

## Example

```typescript
import { CommunicationexternalrecipientRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommunicationexternalrecipientRequest = {
    pkiCommunicationexternalrecipientID,
    sEmailAddress,
    sPhoneE164,
    eCommunicationexternalrecipientType,
    sCommunicationexternalrecipientName,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
