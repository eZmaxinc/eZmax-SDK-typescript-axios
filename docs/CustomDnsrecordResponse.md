# CustomDnsrecordResponse

A Custom Dnsrecord Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**eDnsrecordType** | **string** | The type of the Dnsrecord | [default to undefined]
**eDnsrecordValidation** | **string** | The validation of the Dnsrecord | [default to undefined]
**sDnsrecordName** | **string** | The name of the Dnsrecord | [default to undefined]
**sDnsrecordValue** | **string** | The value of the Dnsrecord | [optional] [default to undefined]
**sDnsrecordExpectedvalue** | **string** | The expected value of the Dnsrecord | [optional] [default to undefined]
**bDnsrecordMustMatch** | **boolean** | Whether the Dnsrecord must match or not | [default to undefined]

## Example

```typescript
import { CustomDnsrecordResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomDnsrecordResponse = {
    eDnsrecordType,
    eDnsrecordValidation,
    sDnsrecordName,
    sDnsrecordValue,
    sDnsrecordExpectedvalue,
    bDnsrecordMustMatch,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
