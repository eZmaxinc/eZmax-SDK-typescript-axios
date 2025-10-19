# CustomCommunicationrecipientsrecipientResponse

Generic AutocompleteElement Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiAgentID** | **number** | The unique ID of the Agent. | [optional] [default to undefined]
**fkiBrokerID** | **number** | The unique ID of the Broker. | [optional] [default to undefined]
**fkiContactID** | **number** | The unique ID of the Contact | [optional] [default to undefined]
**fkiCustomerID** | **number** | The unique ID of the Customer. | [optional] [default to undefined]
**fkiEmployeeID** | **number** | The unique ID of the Employee. | [optional] [default to undefined]
**fkiEzsignsignerID** | **number** | The unique ID of the Ezsignsigner | [optional] [default to undefined]
**fkiFranchiseofficeID** | **number** | The unique ID of the Franchisereoffice | [optional] [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiAgentincorporationID** | **number** | The unique ID of the Agentincorporation. | [optional] [default to undefined]
**fkiAssistantID** | **number** | The unique ID of the Assistant. | [optional] [default to undefined]
**fkiExternalbrokerID** | **number** | The unique ID of the Externalbroker. | [optional] [default to undefined]
**fkiEzcomagentID** | **number** | The unique ID of the Ezcomagent. | [optional] [default to undefined]
**fkiNotaryID** | **number** | The unique ID of the Notary. | [optional] [default to undefined]
**fkiRewardmemberID** | **number** | The unique ID of the Rewardmember. | [optional] [default to undefined]
**fkiSupplierID** | **number** | The unique ID of the Supplier. | [optional] [default to undefined]
**eCommunicationrecipientsrecipientObjecttype** | **string** |  | [default to undefined]
**objContactName** | [**CustomContactNameResponse**](CustomContactNameResponse.md) |  | [default to undefined]
**objEmail** | [**EmailResponseCompound**](EmailResponseCompound.md) |  | [optional] [default to undefined]
**objPhoneFax** | [**PhoneResponseCompound**](PhoneResponseCompound.md) |  | [optional] [default to undefined]
**objPhoneSMS** | [**PhoneResponseCompound**](PhoneResponseCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { CustomCommunicationrecipientsrecipientResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomCommunicationrecipientsrecipientResponse = {
    fkiAgentID,
    fkiBrokerID,
    fkiContactID,
    fkiCustomerID,
    fkiEmployeeID,
    fkiEzsignsignerID,
    fkiFranchiseofficeID,
    fkiUserID,
    fkiAgentincorporationID,
    fkiAssistantID,
    fkiExternalbrokerID,
    fkiEzcomagentID,
    fkiNotaryID,
    fkiRewardmemberID,
    fkiSupplierID,
    eCommunicationrecipientsrecipientObjecttype,
    objContactName,
    objEmail,
    objPhoneFax,
    objPhoneSMS,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
