# CustomCommunicationListElementResponse

A Communication List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiCommunicationID** | **number** | The unique ID of the Communication. | [default to undefined]
**dtCreatedDate** | **string** | The date and time at which the object was created | [default to undefined]
**eCommunicationDirection** | [**ComputedECommunicationDirection**](ComputedECommunicationDirection.md) |  | [default to undefined]
**eCommunicationImportance** | [**FieldECommunicationImportance**](FieldECommunicationImportance.md) |  | [default to undefined]
**eCommunicationType** | [**FieldECommunicationType**](FieldECommunicationType.md) |  | [default to undefined]
**iCommunicationrecipientCount** | **number** | The count of Communicationrecipient | [default to undefined]
**sCommunicationSubject** | **string** | The subject of the Communication | [default to undefined]
**sCommunicationSender** | **string** | The sender name of the Communication | [default to undefined]
**sCommunicationRecipient** | **string** | The recipients\&#39; name of the Communication | [default to undefined]

## Example

```typescript
import { CustomCommunicationListElementResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomCommunicationListElementResponse = {
    pkiCommunicationID,
    dtCreatedDate,
    eCommunicationDirection,
    eCommunicationImportance,
    eCommunicationType,
    iCommunicationrecipientCount,
    sCommunicationSubject,
    sCommunicationSender,
    sCommunicationRecipient,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
