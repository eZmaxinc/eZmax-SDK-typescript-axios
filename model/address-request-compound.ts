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
import { AddressRequest } from './address-request';

/**
 * @type AddressRequestCompound
 * An Address Object and children to create a complete structure
 * @export
 */
/*export type AddressRequestCompound = AddressRequest;*/
export interface AddressRequestCompound {
    /**
     * The unique ID of the Address
     * @type {number}
     * @memberof AddressRequestCompound
     */
    pkiAddressID?:number 
    /**
     * The unique ID of the Addresstype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home| |3|Real Estate Invoice| |4|Invoicing| |5|Shipping|
     * @type {number}
     * @memberof AddressRequestCompound
     */
    fkiAddresstypeID:number 
    /**
     * The Civic number.
     * @type {string}
     * @memberof AddressRequestCompound
     */
    sAddressCivic:string 
    /**
     * The Street Name
     * @type {string}
     * @memberof AddressRequestCompound
     */
    sAddressStreet:string 
    /**
     * The Suite or appartment number
     * @type {string}
     * @memberof AddressRequestCompound
     */
    sAddressSuite?:string 
    /**
     * The City name
     * @type {string}
     * @memberof AddressRequestCompound
     */
    sAddressCity:string 
    /**
     * The unique ID of the Province.  Here are some common values (Complete list must be retrieved from API):  |Value|Description| |-|-| |1|(Canada) Alberta |2|(Canada) British Columbia| |3|(Canada) Manitoba| |3|(Canada) Manitoba| |4|(Canada) New Brunswick| |5|(Canada) Newfoundland| |6|(Canada) Northwest Territories| |7|(Canada) Nova Scotia| |8|(Canada) Nunavut| |9|(Canada) Ontario| |10|(Canada) Prince Edward Island| |11|(Canada) Quebec| |12|(Canada) Saskatchewan| |13|(Canada) Yukon| |14|(United-States) Alabama| |15|(United-States) Alaska| |16|(United-States) Arizona| |17|(United-States) Arkansas| |18|(United-States) California| |19|(United-States) Colorado| |20|(United-States) Connecticut| |21|(United-States) Delaware| |22|(United-States) District of Columbia| |23|(United-States) Florida| |24|(United-States) Georgia| |25|(United-States) Hawaii| |26|(United-States) Idaho| |27|(United-States) Illinois| |28|(United-States) Indiana| |29|(United-States) Iowa| |30|(United-States) Kansas| |31|(United-States) Kentucky| |32|(United-States) Louisiane| |33|(United-States) Maine| |34|(United-States) Maryland| |35|(United-States) Massachusetts| |36|(United-States) Michigan| |37|(United-States) Minnesota| |38|(United-States) Mississippi| |39|(United-States) Missouri| |40|(United-States) Montana| |41|(United-States) Nebraska| |42|(United-States) Nevada| |43|(United-States) New Hampshire| |44|(United-States) New Jersey| |45|(United-States) New Mexico| |46|(United-States) New York| |47|(United-States) North Carolina| |48|(United-States) North Dakota| |49|(United-States) Ohio| |50|(United-States) Oklahoma| |51|(United-States) Oregon| |52|(United-States) Pennsylvania| |53|(United-States) Rhode Island| |54|(United-States) South Carolina| |55|(United-States) South Dakota| |56|(United-States) Tennessee| |57|(United-States) Texas| |58|(United-States) Utah| |60|(United-States) Vermont| |59|(United-States) Virginia| |61|(United-States) Washington| |62|(United-States) West Virginia| |63|(United-States) Wisconsin| |64|(United-States) Wyoming|
     * @type {number}
     * @memberof AddressRequestCompound
     */
    fkiProvinceID:number 
    /**
     * The unique ID of the Country.  Here are some common values (Complete list must be retrieved from API):  |Value|Description| |-|-| |1|Canada| |2|United-States|
     * @type {number}
     * @memberof AddressRequestCompound
     */
    fkiCountryID:number 
    /**
     * The Postal/Zip Code  The value must be entered without spaces
     * @type {string}
     * @memberof AddressRequestCompound
     */
    sAddressZip:string 
    /**
     * The Longitude of the Address
     * @type {string}
     * @memberof AddressRequestCompound
     */
    fAddressLongitude?:string 
    /**
     * The Latitude of the Address
     * @type {string}
     * @memberof AddressRequestCompound
     */
    fAddressLatitude?:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A AddressRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectAddressRequestCompound
 */
export class DataObjectAddressRequestCompound {
    pkiAddressID?:number = undefined
    fkiAddresstypeID:number = 0
    sAddressCivic:string = ''
    sAddressStreet:string = ''
    sAddressSuite?:string = undefined
    sAddressCity:string = ''
    fkiProvinceID:number = 0
    fkiCountryID:number = 0
    sAddressZip:string = ''
    fAddressLongitude?:string = undefined
    fAddressLatitude?:string = undefined
}

/**
 * @export 
 * A AddressRequestCompound Validation Object
 * @class ValidationObjectAddressRequestCompound
 */
export class ValidationObjectAddressRequestCompound {
   pkiAddressID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiAddresstypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sAddressCivic = {
      type: 'string',
      required: true
   }
   sAddressStreet = {
      type: 'string',
      required: true
   }
   sAddressSuite = {
      type: 'string',
      required: false
   }
   sAddressCity = {
      type: 'string',
      required: true
   }
   fkiProvinceID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiCountryID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sAddressZip = {
      type: 'string',
      required: true
   }
   fAddressLongitude = {
      type: 'string',
      pattern: /^(-?)(180(\.0{1,15})?|((1[0-7]\d)|(\d{1,2}))(\.\d{1,15})?)$/,
      required: false
   }
   fAddressLatitude = {
      type: 'string',
      pattern: /^(-?)(90(\.0{1,15})?|([1-8]?\d(\.\d{1,15})?))$/,
      required: false
   }
} 


