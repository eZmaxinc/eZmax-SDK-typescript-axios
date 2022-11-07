/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { ContactinformationsRequestCompound } from './contactinformations-request-compound';

import { DefaultObject } from '../base'

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
 * A ContactRequestCompoundAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectContactRequestCompoundAllOf
 */
export class DefaultObjectContactRequestCompoundAllOf extends DefaultObject {
   objContactinformations:Partial<ContactinformationsRequestCompound> = {}
}


