# LeadListElement

A Lead List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiLeadID** | **number** | The unique ID of the Lead | [default to undefined]
**fkiLeadsourceID** | **number** | The unique ID of the Leadsource | [default to undefined]
**sLeadsourceNameX** | **string** | The name of the Leadsource in the language of the requester | [default to undefined]
**eLeadStatus** | [**FieldELeadStatus**](FieldELeadStatus.md) |  | [default to undefined]
**dtLeadExpiration** | **string** | The expiration of the Lead | [default to undefined]
**bLeadIsactive** | **boolean** | Whether the lead is active or not | [default to undefined]
**sLeadCode** | **string** | The code of the Lead | [default to undefined]

## Example

```typescript
import { LeadListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: LeadListElement = {
    pkiLeadID,
    fkiLeadsourceID,
    sLeadsourceNameX,
    eLeadStatus,
    dtLeadExpiration,
    bLeadIsactive,
    sLeadCode,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
