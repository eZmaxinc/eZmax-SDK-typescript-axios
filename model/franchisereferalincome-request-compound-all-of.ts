/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.47
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { AddressRequest } from './address-request';
import { ContactRequestCompound } from './contact-request-compound';



/**
 * 
 * @export
 * @interface FranchisereferalincomeRequestCompoundAllOf
 */
export interface FranchisereferalincomeRequestCompoundAllOf {
    /**
     * 
     * @type {AddressRequest}
     * @memberof FranchisereferalincomeRequestCompoundAllOf
     */
    objAddress?: AddressRequest;
    /**
     * 
     * @type {Array<ContactRequestCompound>}
     * @memberof FranchisereferalincomeRequestCompoundAllOf
     */
    a_objContact: Array<ContactRequestCompound>;
}
