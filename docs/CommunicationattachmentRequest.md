# CommunicationattachmentRequest

A Communicationattachment Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiCommunicationattachmentID** | **number** | The unique ID of the Communicationattachment | [optional] [default to undefined]
**fkiAttachmentID** | **number** | The unique ID of the Attachment. | [optional] [default to undefined]
**fkiInvoiceID** | **number** | The unique ID of the Invoice. | [optional] [default to undefined]
**fkiSalarypreparationID** | **number** | The unique ID of the Salarypreparation. | [optional] [default to undefined]

## Example

```typescript
import { CommunicationattachmentRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommunicationattachmentRequest = {
    pkiCommunicationattachmentID,
    fkiAttachmentID,
    fkiInvoiceID,
    fkiSalarypreparationID,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
