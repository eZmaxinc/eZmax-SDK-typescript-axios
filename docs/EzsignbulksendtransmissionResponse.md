# EzsignbulksendtransmissionResponse

An Ezsignbulksendtransmission Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignbulksendtransmissionID** | **number** | The unique ID of the Ezsignbulksendtransmission | [default to undefined]
**fkiEzsignbulksendID** | **number** | The unique ID of the Ezsignbulksend | [default to undefined]
**sEzsignbulksendtransmissionDescription** | **string** | The description of the Ezsignbulksendtransmission | [default to undefined]
**iEzsignbulksendtransmissionErrors** | **number** | The number of errors during the Ezsignbulksendtransmission | [default to undefined]
**objAudit** | [**CommonAudit**](CommonAudit.md) |  | [default to undefined]

## Example

```typescript
import { EzsignbulksendtransmissionResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignbulksendtransmissionResponse = {
    pkiEzsignbulksendtransmissionID,
    fkiEzsignbulksendID,
    sEzsignbulksendtransmissionDescription,
    iEzsignbulksendtransmissionErrors,
    objAudit,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
