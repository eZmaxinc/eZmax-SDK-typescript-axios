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
import { BrandingCreateObjectV1ResponseAllOf } from './branding-create-object-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { BrandingCreateObjectV1ResponseMPayload } from './branding-create-object-v1-response-mpayload';
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
 * @type BrandingCreateObjectV1Response
 * Response for POST /1/object/branding
 * @export
 */
export type BrandingCreateObjectV1Response = BrandingCreateObjectV1ResponseAllOf & CommonResponse;


/**
 * @export 
 * A BrandingCreateObjectV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectBrandingCreateObjectV1Response
 */
export class DefaultObjectBrandingCreateObjectV1Response extends DefaultObject {
   mPayload:Partial<BrandingCreateObjectV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


