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
import { AddressRequest } from './address-request';
// May contain unused imports in some cases
// @ts-ignore
import { ContactRequestCompound } from './contact-request-compound';

import { DefaultObject } from '../base'

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
    'objAddress'?: AddressRequest;
    /**
     * 
     * @type {Array<ContactRequestCompound>}
     * @memberof FranchisereferalincomeRequestCompoundAllOf
     */
    'a_objContact': Array<ContactRequestCompound>;
}
/**
 * A FranchisereferalincomeRequestCompoundAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectFranchisereferalincomeRequestCompoundAllOf
 */
export class DefaultObjectFranchisereferalincomeRequestCompoundAllOf extends DefaultObject {
   objAddress?:Partial<AddressRequest> = undefined
   a_objContact:Array<ContactRequestCompound> = []
}


