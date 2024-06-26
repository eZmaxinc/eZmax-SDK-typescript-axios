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
import { EzsignfoldertypeRequestCompound } from './ezsignfoldertype-request-compound';

/**
 * Request for PUT /1/object/ezsignfoldertype/{pkiEzsignfoldertypeID}
 * @export
 * @interface EzsignfoldertypeEditObjectV1Request
 */
export interface EzsignfoldertypeEditObjectV1Request {
    /**
     * 
     * @type {EzsignfoldertypeRequestCompound}
     * @memberof EzsignfoldertypeEditObjectV1Request
     */
    /*'objEzsignfoldertype': EzsignfoldertypeRequestCompound;*/
    'objEzsignfoldertype': EzsignfoldertypeRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfoldertypeRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignfoldertypeRequestCompound } from './'

/**
 * @export 
 * A EzsignfoldertypeEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldertypeEditObjectV1Request
 */
export class DataObjectEzsignfoldertypeEditObjectV1Request {
   objEzsignfoldertype:EzsignfoldertypeRequestCompound = new DataObjectEzsignfoldertypeRequestCompound()
}

/**
 * @export 
 * A EzsignfoldertypeEditObjectV1Request Validation Object
 * @class ValidationObjectEzsignfoldertypeEditObjectV1Request
 */
export class ValidationObjectEzsignfoldertypeEditObjectV1Request {
   objEzsignfoldertype = new ValidationObjectEzsignfoldertypeRequestCompound()
} 


