# ObjectRealestateboardApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**realestateboardGetAutocompleteV2**](#realestateboardgetautocompletev2) | **GET** /2/object/realestateboard/getAutocomplete/{sSelector} | Retrieve Realestateboards and IDs|

# **realestateboardGetAutocompleteV2**
> RealestateboardGetAutocompleteV2Response realestateboardGetAutocompleteV2()

Get the list of realestateboard to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectRealestateboardApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectRealestateboardApi(configuration);

let sSelector: 'All'; //The type of Realestateboards to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let fkiProvinceID: string; //The province ID to filter the results expected (optional) (default to undefined)

const { status, data } = await apiInstance.realestateboardGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage,
    fkiProvinceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Realestateboards to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **fkiProvinceID** | [**string**] | The province ID to filter the results expected | (optional) defaults to undefined|


### Return type

**RealestateboardGetAutocompleteV2Response**

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

