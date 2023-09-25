/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldgroupRequestCompound } from './ezsignformfieldgroup-request-compound';

/**
 * Request for PUT /1/object/ezsignformfieldgroup/{pkiEzsignfoldersignerassociationID}
 * @export
 * @interface EzsignformfieldgroupEditObjectV1Request
 */
export interface EzsignformfieldgroupEditObjectV1Request {
    /**
     * 
     * @type {EzsignformfieldgroupRequestCompound}
     * @memberof EzsignformfieldgroupEditObjectV1Request
     */
    'objEzsignformfieldgroup': EzsignformfieldgroupRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignformfieldgroupRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignformfieldgroupRequestCompound } from './'

/**
 * @export 
 * A EzsignformfieldgroupEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignformfieldgroupEditObjectV1Request
 */
export class DataObjectEzsignformfieldgroupEditObjectV1Request {
   objEzsignformfieldgroup:EzsignformfieldgroupRequestCompound = new DataObjectEzsignformfieldgroupRequestCompound()
}

/**
 * @export 
 * A EzsignformfieldgroupEditObjectV1Request Validation Object
 * @class ValidationObjectEzsignformfieldgroupEditObjectV1Request
 */
export class ValidationObjectEzsignformfieldgroupEditObjectV1Request {
   objEzsignformfieldgroup = new ValidationObjectEzsignformfieldgroupRequestCompound()
} 


