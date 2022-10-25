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
import { EzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload } from './ezsigndocument-edit-ezsignformfieldgroups-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigndocumentEditEzsignformfieldgroupsV1ResponseAllOf
 */
export interface EzsigndocumentEditEzsignformfieldgroupsV1ResponseAllOf {
    /**
     * 
     * @type {EzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload}
     * @memberof EzsigndocumentEditEzsignformfieldgroupsV1ResponseAllOf
     */
    'mPayload': EzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload;
}
/**
 * A EzsigndocumentEditEzsignformfieldgroupsV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentEditEzsignformfieldgroupsV1ResponseAllOf
 */
export class DefaultObjectEzsigndocumentEditEzsignformfieldgroupsV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigndocumentEditEzsignformfieldgroupsV1ResponseMPayload> = {}
}


