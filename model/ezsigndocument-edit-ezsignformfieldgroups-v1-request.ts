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
import { EzsignformfieldgroupRequestCompound } from './ezsignformfieldgroup-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for PUT /1/object/ezsigndocument/{pkiEzsigndocumentID}/editEzsignformfieldgroups
 * @export
 * @interface EzsigndocumentEditEzsignformfieldgroupsV1Request
 */
export interface EzsigndocumentEditEzsignformfieldgroupsV1Request {
    /**
     * 
     * @type {Array<EzsignformfieldgroupRequestCompound>}
     * @memberof EzsigndocumentEditEzsignformfieldgroupsV1Request
     */
    'a_objEzsignformfieldgroup': Array<EzsignformfieldgroupRequestCompound>;
}
/**
 * A EzsigndocumentEditEzsignformfieldgroupsV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentEditEzsignformfieldgroupsV1Request
 */
export class DefaultObjectEzsigndocumentEditEzsignformfieldgroupsV1Request extends DefaultObject {
   a_objEzsignformfieldgroup:Array<EzsignformfieldgroupRequestCompound> = []
}


