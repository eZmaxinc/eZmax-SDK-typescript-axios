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
import { ContactinformationsRequestCompound } from './contactinformations-request-compound';

/**
 * 
 * @export
 * @interface ContactRequestCompoundAllOf
 */
export interface ContactRequestCompoundAllOf {
    /**
     * 
     * @type {ContactinformationsRequestCompound}
     * @memberof ContactRequestCompoundAllOf
     */
    'objContactinformations': ContactinformationsRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectContactinformationsRequestCompound } from './'
// @ts-ignore
import { ValidationObjectContactinformationsRequestCompound } from './'

/**
 * @export 
 * A ContactRequestCompoundAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectContactRequestCompoundAllOf
 */
export class DataObjectContactRequestCompoundAllOf {
   objContactinformations:ContactinformationsRequestCompound = new DataObjectContactinformationsRequestCompound()
}

/**
 * @export 
 * A ContactRequestCompoundAllOf Validation Object
 * @class ValidationObjectContactRequestCompoundAllOf
 */
export class ValidationObjectContactRequestCompoundAllOf {
   objContactinformations = new ValidationObjectContactinformationsRequestCompound()
} 


