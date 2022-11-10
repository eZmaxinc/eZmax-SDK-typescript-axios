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
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseAllOf } from './ezsigntemplatedocument-edit-ezsigntemplateformfieldgroups-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload } from './ezsigntemplatedocument-edit-ezsigntemplateformfieldgroups-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response
 * Response for PUT /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/editEzsigntemplateformfieldgroups
 * @export
 */
export type EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response = CommonResponse & EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseAllOf;


/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response
 */
export class DefaultObjectEzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response extends DefaultObject {
   mPayload:Partial<EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


