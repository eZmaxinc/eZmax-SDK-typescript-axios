# CommunicationrecipientRequest

A Communicationrecipient Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiCommunicationrecipientID** | **number** | The unique ID of the Communicationrecipient. | [optional] [default to undefined]
**fkiAgentID** | **number** | The unique ID of the Agent. | [optional] [default to undefined]
**fkiBrokerID** | **number** | The unique ID of the Broker. | [optional] [default to undefined]
**fkiContactID** | **number** | The unique ID of the Contact | [optional] [default to undefined]
**fkiCustomerID** | **number** | The unique ID of the Customer. | [optional] [default to undefined]
**fkiEmployeeID** | **number** | The unique ID of the Employee. | [optional] [default to undefined]
**fkiAssistantID** | **number** | The unique ID of the Assistant. | [optional] [default to undefined]
**fkiExternalbrokerID** | **number** | The unique ID of the Externalbroker. | [optional] [default to undefined]
**fkiEzsignsignerID** | **number** | The unique ID of the Ezsignsigner | [optional] [default to undefined]
**fkiNotaryID** | **number** | The unique ID of the Notary. | [optional] [default to undefined]
**fkiSupplierID** | **number** | The unique ID of the Supplier. | [optional] [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiMailboxsharedID** | **number** | The unique ID of the Mailboxshared | [optional] [default to undefined]
**fkiPhonelinesharedID** | **number** | The unique ID of the Phonelineshared | [optional] [default to undefined]
**eCommunicationrecipientType** | [**FieldECommunicationrecipientType**](FieldECommunicationrecipientType.md) |  | [optional] [default to undefined]

## Example

```typescript
import { CommunicationrecipientRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommunicationrecipientRequest = {
    pkiCommunicationrecipientID,
    fkiAgentID,
    fkiBrokerID,
    fkiContactID,
    fkiCustomerID,
    fkiEmployeeID,
    fkiAssistantID,
    fkiExternalbrokerID,
    fkiEzsignsignerID,
    fkiNotaryID,
    fkiSupplierID,
    fkiUserID,
    fkiMailboxsharedID,
    fkiPhonelinesharedID,
    eCommunicationrecipientType,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
