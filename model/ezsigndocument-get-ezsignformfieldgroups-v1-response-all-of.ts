/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload } from './ezsigndocument-get-ezsignformfieldgroups-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsigndocumentGetEzsignformfieldgroupsV1ResponseAllOf
 */
export interface EzsigndocumentGetEzsignformfieldgroupsV1ResponseAllOf {
    /**
     * 
     * @type {EzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload}
     * @memberof EzsigndocumentGetEzsignformfieldgroupsV1ResponseAllOf
     */
    'mPayload': EzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigndocumentGetEzsignformfieldgroupsV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetEzsignformfieldgroupsV1ResponseAllOf
 */
export class DataObjectEzsigndocumentGetEzsignformfieldgroupsV1ResponseAllOf {
   mPayload:EzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload = new DataObjectEzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigndocumentGetEzsignformfieldgroupsV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsigndocumentGetEzsignformfieldgroupsV1ResponseAllOf
 */
export class ValidationObjectEzsigndocumentGetEzsignformfieldgroupsV1ResponseAllOf {
   mPayload = new ValidationObjectEzsigndocumentGetEzsignformfieldgroupsV1ResponseMPayload()
} 


