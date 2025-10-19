# DomainResponse

A Domain Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiDomainID** | **number** | The unique ID of the Domain | [default to undefined]
**sDomainName** | **string** | The name of the Domain | [default to undefined]
**bDomainValiddkim** | **boolean** | Whether the DKIM is valid or not | [default to undefined]
**bDomainValidmailfrom** | **boolean** | Whether the mail from is valid or not | [default to undefined]
**bDomainValidcustomer** | **boolean** | Whether the customer has access to it or not | [default to undefined]
**objAudit** | [**CommonAudit**](CommonAudit.md) |  | [default to undefined]

## Example

```typescript
import { DomainResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DomainResponse = {
    pkiDomainID,
    sDomainName,
    bDomainValiddkim,
    bDomainValidmailfrom,
    bDomainValidcustomer,
    objAudit,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
