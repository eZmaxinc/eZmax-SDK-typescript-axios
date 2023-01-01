/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
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
import { EzsigndocumentGetEzsignformfieldgroupsV1ResponseAllOf } from './ezsigndocument-get-ezsignformfieldgroups-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload } from './ezsigndocument-get-ezsignformfieldgroups-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsigndocumentGetEzsignformfieldgroupsV1Response
 * Response for GET /1/object/ezsigndocument/{pkiEzsigndocument}/getEzsignformfieldgroups
 * @export
 */
export type EzsigndocumentGetEzsignformfieldgroupsV1Response = CommonResponse & EzsigndocumentGetEzsignformfieldgroupsV1ResponseAllOf;


/**
 * @export 
 * A EzsigndocumentGetEzsignformfieldgroupsV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigndocumentGetEzsignformfieldgroupsV1Response
 */
export class DefaultObjectEzsigndocumentGetEzsignformfieldgroupsV1Response extends DefaultObject {
   mPayload:Partial<EzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


