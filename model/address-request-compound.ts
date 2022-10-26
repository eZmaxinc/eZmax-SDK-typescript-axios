/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { AddressRequest } from './address-request';

import { DefaultObject } from '../base'

/**
 * @type AddressRequestCompound
 * An Address Object and children to create a complete structure
 * @export
 */
export type AddressRequestCompound = AddressRequest;


/**
 * @export 
 * A AddressRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectAddressRequestCompound
 */
export class DefaultObjectAddressRequestCompound extends DefaultObject {
   fkiAddresstypeID:number = 0
   sAddressCivic:string = ''
   sAddressStreet:string = ''
   sAddressSuite:string = ''
   sAddressCity:string = ''
   fkiProvinceID:number = 0
   fkiCountryID:number = 0
   sAddressZip:string = ''
}


