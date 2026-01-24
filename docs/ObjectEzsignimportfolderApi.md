# ObjectEzsignimportfolderApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignimportfolderDeleteObjectV1**](#ezsignimportfolderdeleteobjectv1) | **DELETE** /1/object/ezsignimportfolder/{pkiEzsignimportfolderID} | Delete an existing Ezsignimportfolder|
|[**ezsignimportfolderGetListV1**](#ezsignimportfoldergetlistv1) | **GET** /1/object/ezsignimportfolder/getList | Retrieve Ezsignimportfolder list|
|[**ezsignimportfolderGetObjectV2**](#ezsignimportfoldergetobjectv2) | **GET** /2/object/ezsignimportfolder/{pkiEzsignimportfolderID} | Retrieve an existing Ezsignimportfolder|

# **ezsignimportfolderDeleteObjectV1**
> EzsignimportfolderDeleteObjectV1Response ezsignimportfolderDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsignimportfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignimportfolderApi(configuration);

let pkiEzsignimportfolderID: number; //The unique ID of the Ezsignimportfolder (default to undefined)

const { status, data } = await apiInstance.ezsignimportfolderDeleteObjectV1(
    pkiEzsignimportfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignimportfolderID** | [**number**] | The unique ID of the Ezsignimportfolder | defaults to undefined|


### Return type

**EzsignimportfolderDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignimportfolderGetListV1**
> EzsignimportfolderGetListV1Response ezsignimportfolderGetListV1()



### Example

```typescript
import {
    ObjectEzsignimportfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignimportfolderApi(configuration);

let eOrderBy: 'pkiEzsignimportfolderID_ASC' | 'pkiEzsignimportfolderID_DESC' | 'sEzsignimportfolderName_ASC' | 'sEzsignimportfolderName_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezsignimportfolderGetListV1(
    eOrderBy,
    iRowMax,
    iRowOffset,
    acceptLanguage,
    sFilter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eOrderBy** | [**&#39;pkiEzsignimportfolderID_ASC&#39; | &#39;pkiEzsignimportfolderID_DESC&#39; | &#39;sEzsignimportfolderName_ASC&#39; | &#39;sEzsignimportfolderName_DESC&#39;**]**Array<&#39;pkiEzsignimportfolderID_ASC&#39; &#124; &#39;pkiEzsignimportfolderID_DESC&#39; &#124; &#39;sEzsignimportfolderName_ASC&#39; &#124; &#39;sEzsignimportfolderName_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**EzsignimportfolderGetListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignimportfolderGetObjectV2**
> EzsignimportfolderGetObjectV2Response ezsignimportfolderGetObjectV2()



### Example

```typescript
import {
    ObjectEzsignimportfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignimportfolderApi(configuration);

let pkiEzsignimportfolderID: number; //The unique ID of the Ezsignimportfolder (default to undefined)

const { status, data } = await apiInstance.ezsignimportfolderGetObjectV2(
    pkiEzsignimportfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignimportfolderID** | [**number**] | The unique ID of the Ezsignimportfolder | defaults to undefined|


### Return type

**EzsignimportfolderGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

