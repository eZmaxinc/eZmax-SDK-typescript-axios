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
import { VariableexpenseResponseCompound } from './variableexpense-response-compound';

/**
 * Payload for GET /2/object/variableexpense/{pkiVariableexpenseID}
 * @export
 * @interface VariableexpenseGetObjectV2ResponseMPayload
 */
export interface VariableexpenseGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {VariableexpenseResponseCompound}
     * @memberof VariableexpenseGetObjectV2ResponseMPayload
     */
    /*'objVariableexpense': VariableexpenseResponseCompound;*/
    'objVariableexpense': VariableexpenseResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectVariableexpenseResponseCompound } from './'
// @ts-ignore
import { ValidationObjectVariableexpenseResponseCompound } from './'

/**
 * @export 
 * A VariableexpenseGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectVariableexpenseGetObjectV2ResponseMPayload
 */
export class DataObjectVariableexpenseGetObjectV2ResponseMPayload {
   objVariableexpense:VariableexpenseResponseCompound = new DataObjectVariableexpenseResponseCompound()
}

/**
 * @export 
 * A VariableexpenseGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectVariableexpenseGetObjectV2ResponseMPayload
 */
export class ValidationObjectVariableexpenseGetObjectV2ResponseMPayload {
   objVariableexpense = new ValidationObjectVariableexpenseResponseCompound()
} 


