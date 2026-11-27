# ObjectEzmaxpartnerproductstageApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezmaxpartnerproductstageGetEzmaxpartnerproductstagepermissionsV1**](#ezmaxpartnerproductstagegetezmaxpartnerproductstagepermissionsv1) | **GET** /1/object/ezmaxpartnerproductstage/{pkiEzmaxpartnerproductstageID}/getEzmaxpartnerproductstagepermissions | Retrieve an existing Ezmaxpartnerproductstage\&#39;s Ezmaxpartnerproductstagepermissions|
|[**ezmaxpartnerproductstageGetEzmaxpartnerproductstagewebhooksV1**](#ezmaxpartnerproductstagegetezmaxpartnerproductstagewebhooksv1) | **GET** /1/object/ezmaxpartnerproductstage/{pkiEzmaxpartnerproductstageID}/getEzmaxpartnerproductstagewebhooks | Retrieve an existing Ezmaxpartnerproductstage\&#39;s Ezmaxpartnerproductstagewebhooks|
|[**ezmaxpartnerproductstageGetListV1**](#ezmaxpartnerproductstagegetlistv1) | **GET** /1/object/ezmaxpartnerproductstage/getList | Retrieve Ezmaxpartnerproductstage list|
|[**ezmaxpartnerproductstageGetObjectV2**](#ezmaxpartnerproductstagegetobjectv2) | **GET** /2/object/ezmaxpartnerproductstage/{pkiEzmaxpartnerproductstageID} | Retrieve an existing Ezmaxpartnerproductstage|
|[**ezmaxpartnerproductstageSubscribeV1**](#ezmaxpartnerproductstagesubscribev1) | **POST** /1/object/ezmaxpartnerproductstage/{pkiEzmaxpartnerproductstageID}/subscribe | Subscribe to the Ezmaxpartnerproductstage|
|[**ezmaxpartnerproductstageUnsubscribeV1**](#ezmaxpartnerproductstageunsubscribev1) | **POST** /1/object/ezmaxpartnerproductstage/{pkiEzmaxpartnerproductstageID}/unsubscribe | Unsubscribe to the Ezmaxpartnerproductstage|

# **ezmaxpartnerproductstageGetEzmaxpartnerproductstagepermissionsV1**
> EzmaxpartnerproductstageGetEzmaxpartnerproductstagepermissionsV1Response ezmaxpartnerproductstageGetEzmaxpartnerproductstagepermissionsV1()


### Example

```typescript
import {
    ObjectEzmaxpartnerproductstageApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzmaxpartnerproductstageApi(configuration);

let pkiEzmaxpartnerproductstageID: number; // (default to undefined)

const { status, data } = await apiInstance.ezmaxpartnerproductstageGetEzmaxpartnerproductstagepermissionsV1(
    pkiEzmaxpartnerproductstageID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzmaxpartnerproductstageID** | [**number**] |  | defaults to undefined|


### Return type

**EzmaxpartnerproductstageGetEzmaxpartnerproductstagepermissionsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezmaxpartnerproductstageGetEzmaxpartnerproductstagewebhooksV1**
> EzmaxpartnerproductstageGetEzmaxpartnerproductstagewebhooksV1Response ezmaxpartnerproductstageGetEzmaxpartnerproductstagewebhooksV1()


### Example

```typescript
import {
    ObjectEzmaxpartnerproductstageApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzmaxpartnerproductstageApi(configuration);

let pkiEzmaxpartnerproductstageID: number; // (default to undefined)

const { status, data } = await apiInstance.ezmaxpartnerproductstageGetEzmaxpartnerproductstagewebhooksV1(
    pkiEzmaxpartnerproductstageID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzmaxpartnerproductstageID** | [**number**] |  | defaults to undefined|


### Return type

**EzmaxpartnerproductstageGetEzmaxpartnerproductstagewebhooksV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezmaxpartnerproductstageGetListV1**
> EzmaxpartnerproductstageGetListV1Response ezmaxpartnerproductstageGetListV1()



### Example

```typescript
import {
    ObjectEzmaxpartnerproductstageApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzmaxpartnerproductstageApi(configuration);

let eOrderBy: 'pkiEzmaxpartnerproductstageID_ASC' | 'pkiEzmaxpartnerproductstageID_DESC' | 'efksEzmaxcustomerCode_ASC' | 'efksEzmaxcustomerCode_DESC' | 'fkiEzmaxpartnerproductID_ASC' | 'fkiEzmaxpartnerproductID_DESC' | 'sEzmaxpartnerproductNameX_ASC' | 'sEzmaxpartnerproductNameX_DESC' | 'sEzmaxpartnerproductShortdescriptionX_ASC' | 'sEzmaxpartnerproductShortdescriptionX_DESC' | 'sEzmaxpartnerproductLogourlX_ASC' | 'sEzmaxpartnerproductLogourlX_DESC' | 'fkiEzmaxpartnerID_ASC' | 'fkiEzmaxpartnerID_DESC' | 'sEzmaxpartnerNameX_ASC' | 'sEzmaxpartnerNameX_DESC' | 'eEzmaxpartnerproductstageCode_ASC' | 'eEzmaxpartnerproductstageCode_DESC' | 'bEzmaxpartnerproductstagePublished_ASC' | 'bEzmaxpartnerproductstagePublished_DESC' | 'bEzmaxpartnerproductstageInstalled_ASC' | 'bEzmaxpartnerproductstageInstalled_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezmaxpartnerproductstageGetListV1(
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
| **eOrderBy** | [**&#39;pkiEzmaxpartnerproductstageID_ASC&#39; | &#39;pkiEzmaxpartnerproductstageID_DESC&#39; | &#39;efksEzmaxcustomerCode_ASC&#39; | &#39;efksEzmaxcustomerCode_DESC&#39; | &#39;fkiEzmaxpartnerproductID_ASC&#39; | &#39;fkiEzmaxpartnerproductID_DESC&#39; | &#39;sEzmaxpartnerproductNameX_ASC&#39; | &#39;sEzmaxpartnerproductNameX_DESC&#39; | &#39;sEzmaxpartnerproductShortdescriptionX_ASC&#39; | &#39;sEzmaxpartnerproductShortdescriptionX_DESC&#39; | &#39;sEzmaxpartnerproductLogourlX_ASC&#39; | &#39;sEzmaxpartnerproductLogourlX_DESC&#39; | &#39;fkiEzmaxpartnerID_ASC&#39; | &#39;fkiEzmaxpartnerID_DESC&#39; | &#39;sEzmaxpartnerNameX_ASC&#39; | &#39;sEzmaxpartnerNameX_DESC&#39; | &#39;eEzmaxpartnerproductstageCode_ASC&#39; | &#39;eEzmaxpartnerproductstageCode_DESC&#39; | &#39;bEzmaxpartnerproductstagePublished_ASC&#39; | &#39;bEzmaxpartnerproductstagePublished_DESC&#39; | &#39;bEzmaxpartnerproductstageInstalled_ASC&#39; | &#39;bEzmaxpartnerproductstageInstalled_DESC&#39;**]**Array<&#39;pkiEzmaxpartnerproductstageID_ASC&#39; &#124; &#39;pkiEzmaxpartnerproductstageID_DESC&#39; &#124; &#39;efksEzmaxcustomerCode_ASC&#39; &#124; &#39;efksEzmaxcustomerCode_DESC&#39; &#124; &#39;fkiEzmaxpartnerproductID_ASC&#39; &#124; &#39;fkiEzmaxpartnerproductID_DESC&#39; &#124; &#39;sEzmaxpartnerproductNameX_ASC&#39; &#124; &#39;sEzmaxpartnerproductNameX_DESC&#39; &#124; &#39;sEzmaxpartnerproductShortdescriptionX_ASC&#39; &#124; &#39;sEzmaxpartnerproductShortdescriptionX_DESC&#39; &#124; &#39;sEzmaxpartnerproductLogourlX_ASC&#39; &#124; &#39;sEzmaxpartnerproductLogourlX_DESC&#39; &#124; &#39;fkiEzmaxpartnerID_ASC&#39; &#124; &#39;fkiEzmaxpartnerID_DESC&#39; &#124; &#39;sEzmaxpartnerNameX_ASC&#39; &#124; &#39;sEzmaxpartnerNameX_DESC&#39; &#124; &#39;eEzmaxpartnerproductstageCode_ASC&#39; &#124; &#39;eEzmaxpartnerproductstageCode_DESC&#39; &#124; &#39;bEzmaxpartnerproductstagePublished_ASC&#39; &#124; &#39;bEzmaxpartnerproductstagePublished_DESC&#39; &#124; &#39;bEzmaxpartnerproductstageInstalled_ASC&#39; &#124; &#39;bEzmaxpartnerproductstageInstalled_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**EzmaxpartnerproductstageGetListV1Response**

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

# **ezmaxpartnerproductstageGetObjectV2**
> EzmaxpartnerproductstageGetObjectV2Response ezmaxpartnerproductstageGetObjectV2()



### Example

```typescript
import {
    ObjectEzmaxpartnerproductstageApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzmaxpartnerproductstageApi(configuration);

let pkiEzmaxpartnerproductstageID: number; //The unique ID of the Ezmaxpartnerproductstage (default to undefined)

const { status, data } = await apiInstance.ezmaxpartnerproductstageGetObjectV2(
    pkiEzmaxpartnerproductstageID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzmaxpartnerproductstageID** | [**number**] | The unique ID of the Ezmaxpartnerproductstage | defaults to undefined|


### Return type

**EzmaxpartnerproductstageGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezmaxpartnerproductstageSubscribeV1**
> EzmaxpartnerproductstageSubscribeV1Response ezmaxpartnerproductstageSubscribeV1(body)


### Example

```typescript
import {
    ObjectEzmaxpartnerproductstageApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzmaxpartnerproductstageApi(configuration);

let pkiEzmaxpartnerproductstageID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.ezmaxpartnerproductstageSubscribeV1(
    pkiEzmaxpartnerproductstageID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiEzmaxpartnerproductstageID** | [**number**] |  | defaults to undefined|


### Return type

**EzmaxpartnerproductstageSubscribeV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezmaxpartnerproductstageUnsubscribeV1**
> EzmaxpartnerproductstageUnsubscribeV1Response ezmaxpartnerproductstageUnsubscribeV1(body)


### Example

```typescript
import {
    ObjectEzmaxpartnerproductstageApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzmaxpartnerproductstageApi(configuration);

let pkiEzmaxpartnerproductstageID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.ezmaxpartnerproductstageUnsubscribeV1(
    pkiEzmaxpartnerproductstageID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiEzmaxpartnerproductstageID** | [**number**] |  | defaults to undefined|


### Return type

**EzmaxpartnerproductstageUnsubscribeV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

