/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { BrandingGetObjectV2ResponseAllOf } from './branding-get-object-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { BrandingGetObjectV2ResponseMPayload } from './branding-get-object-v2-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';

import { DefaultObject } from '../base'

/**
 * @type BrandingGetObjectV2Response
 * Response for GET /2/object/branding/{pkiBrandingID}
 * @export
 */
export type BrandingGetObjectV2Response = BrandingGetObjectV2ResponseAllOf & CommonResponse;


/**
 * @export 
 * A BrandingGetObjectV2Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectBrandingGetObjectV2Response
 */
export class DefaultObjectBrandingGetObjectV2Response extends DefaultObject {
   mPayload:Partial<BrandingGetObjectV2ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


