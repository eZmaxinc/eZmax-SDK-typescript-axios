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
import type { ContactRequestV2 } from './contact-request-v2';
// May contain unused imports in some cases
// @ts-ignore
import type { ContactinformationsRequestCompoundV2 } from './contactinformations-request-compound-v2';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEContactType } from './field-econtact-type';

/**
 * @type ContactRequestCompoundV2
 * A Contact Object and children to create a complete structure
 * @export
 */
/*export type ContactRequestCompoundV2 = ContactRequestV2;*/
export interface ContactRequestCompoundV2 {
    /**
     * 
     * @type {ContactinformationsRequestCompoundV2}
     * @memberof ContactRequestCompoundV2
     */
    objContactinformations:ContactinformationsRequestCompoundV2 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectContactinformationsRequestCompoundV2 } from './'
// @ts-ignore
import { ValidationObjectContactinformationsRequestCompoundV2 } from './'

/**
 * @export 
 * A ContactRequestCompoundV2 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectContactRequestCompoundV2
 */
export class DataObjectContactRequestCompoundV2 {
    objContactinformations:ContactinformationsRequestCompoundV2 = new DataObjectContactinformationsRequestCompoundV2()
}

/**
 * @export 
 * A ContactRequestCompoundV2 Validation Object
 * @class ValidationObjectContactRequestCompoundV2
 */
export class ValidationObjectContactRequestCompoundV2 {
   objContactinformations = new ValidationObjectContactinformationsRequestCompoundV2()
} 


