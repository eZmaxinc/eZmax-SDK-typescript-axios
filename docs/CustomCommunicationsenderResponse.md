# CustomCommunicationsenderResponse

Generic Communicationsender Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiAgentID** | **number** | The unique ID of the Agent. | [optional] [default to undefined]
**fkiBrokerID** | **number** | The unique ID of the Broker. | [optional] [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiMailboxsharedID** | **number** | The unique ID of the Mailboxshared | [optional] [default to undefined]
**fkiPhonelinesharedID** | **number** | The unique ID of the Phonelineshared | [optional] [default to undefined]
**eCommunicationsenderObjecttype** | **string** |  | [default to undefined]
**objContactName** | [**CustomContactNameResponse**](CustomContactNameResponse.md) |  | [default to undefined]
**objEmail** | [**EmailResponseCompound**](EmailResponseCompound.md) |  | [optional] [default to undefined]
**objPhoneFax** | [**PhoneResponseCompound**](PhoneResponseCompound.md) |  | [optional] [default to undefined]
**objPhoneSMS** | [**PhoneResponseCompound**](PhoneResponseCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { CustomCommunicationsenderResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomCommunicationsenderResponse = {
    fkiAgentID,
    fkiBrokerID,
    fkiUserID,
    fkiMailboxsharedID,
    fkiPhonelinesharedID,
    eCommunicationsenderObjecttype,
    objContactName,
    objEmail,
    objPhoneFax,
    objPhoneSMS,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
