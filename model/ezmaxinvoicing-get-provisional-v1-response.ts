/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingGetProvisionalV1ResponseAllOf } from './ezmaxinvoicing-get-provisional-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingGetProvisionalV1ResponseMPayload } from './ezmaxinvoicing-get-provisional-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzmaxinvoicingGetProvisionalV1Response
 * Response for GET /1/object/ezmaxinvoicing/getProvisional
 * @export
 */
export type EzmaxinvoicingGetProvisionalV1Response = CommonResponse & EzmaxinvoicingGetProvisionalV1ResponseAllOf;


/**
 * @export 
 * A EzmaxinvoicingGetProvisionalV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzmaxinvoicingGetProvisionalV1Response
 */
export class DefaultObjectEzmaxinvoicingGetProvisionalV1Response extends DefaultObject {
   mPayload:Partial<EzmaxinvoicingGetProvisionalV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


