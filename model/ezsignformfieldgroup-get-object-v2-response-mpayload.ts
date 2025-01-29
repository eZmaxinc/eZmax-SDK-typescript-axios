/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { EzsignformfieldgroupResponseCompound } from './ezsignformfieldgroup-response-compound';

/**
 * Payload for GET /2/object/ezsignformfieldgroup/{pkiEzsignformfieldgroupID}
 * @export
 * @interface EzsignformfieldgroupGetObjectV2ResponseMPayload
 */
export interface EzsignformfieldgroupGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsignformfieldgroupResponseCompound}
     * @memberof EzsignformfieldgroupGetObjectV2ResponseMPayload
     */
    /*'objEzsignformfieldgroup': EzsignformfieldgroupResponseCompound;*/
    'objEzsignformfieldgroup': EzsignformfieldgroupResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignformfieldgroupResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignformfieldgroupResponseCompound } from './'

/**
 * @export 
 * A EzsignformfieldgroupGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignformfieldgroupGetObjectV2ResponseMPayload
 */
export class DataObjectEzsignformfieldgroupGetObjectV2ResponseMPayload {
   objEzsignformfieldgroup:EzsignformfieldgroupResponseCompound = new DataObjectEzsignformfieldgroupResponseCompound()
}

/**
 * @export 
 * A EzsignformfieldgroupGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsignformfieldgroupGetObjectV2ResponseMPayload
 */
export class ValidationObjectEzsignformfieldgroupGetObjectV2ResponseMPayload {
   objEzsignformfieldgroup = new ValidationObjectEzsignformfieldgroupResponseCompound()
} 


