/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
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
import { EzsignformfieldgroupGetObjectV1ResponseAllOf } from './ezsignformfieldgroup-get-object-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldgroupGetObjectV1ResponseMPayload } from './ezsignformfieldgroup-get-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsignformfieldgroupGetObjectV1Response
 * Response for GET /1/object/ezsignformfieldgroup/{pkiEzsignformfieldgroupID}
 * @export
 */
export type EzsignformfieldgroupGetObjectV1Response = CommonResponse & EzsignformfieldgroupGetObjectV1ResponseAllOf;


/**
 * @export 
 * A EzsignformfieldgroupGetObjectV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignformfieldgroupGetObjectV1Response
 */
export class DefaultObjectEzsignformfieldgroupGetObjectV1Response extends DefaultObject {
   mPayload:Partial<EzsignformfieldgroupGetObjectV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


