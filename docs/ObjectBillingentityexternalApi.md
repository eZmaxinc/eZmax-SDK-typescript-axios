# ObjectBillingentityexternalApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**billingentityexternalGenerateFederationTokenV1**](#billingentityexternalgeneratefederationtokenv1) | **POST** /1/object/billingentityexternal/{pkiBillingentityexternalID}/generateFederationToken | Generate a federation token|
|[**billingentityexternalGetAutocompleteV2**](#billingentityexternalgetautocompletev2) | **GET** /2/object/billingentityexternal/getAutocomplete/{sSelector} | Retrieve Billingentityexternals and IDs|

# **billingentityexternalGenerateFederationTokenV1**
> BillingentityexternalGenerateFederationTokenV1Response billingentityexternalGenerateFederationTokenV1(billingentityexternalGenerateFederationTokenV1Request)



### Example

```typescript
import {
    ObjectBillingentityexternalApi,
    Configuration,
    BillingentityexternalGenerateFederationTokenV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBillingentityexternalApi(configuration);

let pkiBillingentityexternalID: number; // (default to undefined)
let billingentityexternalGenerateFederationTokenV1Request: BillingentityexternalGenerateFederationTokenV1Request; //

const { status, data } = await apiInstance.billingentityexternalGenerateFederationTokenV1(
    pkiBillingentityexternalID,
    billingentityexternalGenerateFederationTokenV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **billingentityexternalGenerateFederationTokenV1Request** | **BillingentityexternalGenerateFederationTokenV1Request**|  | |
| **pkiBillingentityexternalID** | [**number**] |  | defaults to undefined|


### Return type

**BillingentityexternalGenerateFederationTokenV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **billingentityexternalGetAutocompleteV2**
> BillingentityexternalGetAutocompleteV2Response billingentityexternalGetAutocompleteV2()

Get the list of Billingentityexternal to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectBillingentityexternalApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBillingentityexternalApi(configuration);

let sSelector: 'All'; //The type of Billingentityexternals to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.billingentityexternalGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Billingentityexternals to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**BillingentityexternalGetAutocompleteV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

