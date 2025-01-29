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



/**
 * A Province AutocompleteElement Response
 * @export
 * @interface ProvinceAutocompleteElementResponse
 */
export interface ProvinceAutocompleteElementResponse {
    /**
     * The unique ID of the Province.  Here are some common values (Complete list must be retrieved from API):  |Value|Description| |-|-| |1|(Canada) Alberta |2|(Canada) British Columbia| |3|(Canada) Manitoba| |3|(Canada) Manitoba| |4|(Canada) New Brunswick| |5|(Canada) Newfoundland| |6|(Canada) Northwest Territories| |7|(Canada) Nova Scotia| |8|(Canada) Nunavut| |9|(Canada) Ontario| |10|(Canada) Prince Edward Island| |11|(Canada) Quebec| |12|(Canada) Saskatchewan| |13|(Canada) Yukon| |14|(United-States) Alabama| |15|(United-States) Alaska| |16|(United-States) Arizona| |17|(United-States) Arkansas| |18|(United-States) California| |19|(United-States) Colorado| |20|(United-States) Connecticut| |21|(United-States) Delaware| |22|(United-States) District of Columbia| |23|(United-States) Florida| |24|(United-States) Georgia| |25|(United-States) Hawaii| |26|(United-States) Idaho| |27|(United-States) Illinois| |28|(United-States) Indiana| |29|(United-States) Iowa| |30|(United-States) Kansas| |31|(United-States) Kentucky| |32|(United-States) Louisiane| |33|(United-States) Maine| |34|(United-States) Maryland| |35|(United-States) Massachusetts| |36|(United-States) Michigan| |37|(United-States) Minnesota| |38|(United-States) Mississippi| |39|(United-States) Missouri| |40|(United-States) Montana| |41|(United-States) Nebraska| |42|(United-States) Nevada| |43|(United-States) New Hampshire| |44|(United-States) New Jersey| |45|(United-States) New Mexico| |46|(United-States) New York| |47|(United-States) North Carolina| |48|(United-States) North Dakota| |49|(United-States) Ohio| |50|(United-States) Oklahoma| |51|(United-States) Oregon| |52|(United-States) Pennsylvania| |53|(United-States) Rhode Island| |54|(United-States) South Carolina| |55|(United-States) South Dakota| |56|(United-States) Tennessee| |57|(United-States) Texas| |58|(United-States) Utah| |60|(United-States) Vermont| |59|(United-States) Virginia| |61|(United-States) Washington| |62|(United-States) West Virginia| |63|(United-States) Wisconsin| |64|(United-States) Wyoming|
     * @type {number}
     * @memberof ProvinceAutocompleteElementResponse
     */
    /*'pkiProvinceID': number;*/
    'pkiProvinceID': number;
    /**
     * The unique ID of the Country.  Here are some common values (Complete list must be retrieved from API):  |Value|Description| |-|-| |1|Canada| |2|United-States|
     * @type {number}
     * @memberof ProvinceAutocompleteElementResponse
     */
    /*'fkiCountryID': number;*/
    'fkiCountryID': number;
    /**
     * The name of the Province in the language of the requester
     * @type {string}
     * @memberof ProvinceAutocompleteElementResponse
     */
    /*'sProvinceNameX': string;*/
    'sProvinceNameX': string;
    /**
     * The shortname of the Province
     * @type {string}
     * @memberof ProvinceAutocompleteElementResponse
     */
    /*'sProvinceShortname': string;*/
    'sProvinceShortname': string;
    /**
     * Whether the Province is active or not
     * @type {boolean}
     * @memberof ProvinceAutocompleteElementResponse
     */
    /*'bProvinceIsactive': boolean;*/
    'bProvinceIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ProvinceAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectProvinceAutocompleteElementResponse
 */
export class DataObjectProvinceAutocompleteElementResponse {
   pkiProvinceID:number = 0
   fkiCountryID:number = 0
   sProvinceNameX:string = ''
   sProvinceShortname:string = ''
   bProvinceIsactive:boolean = false
}

/**
 * @export 
 * A ProvinceAutocompleteElementResponse Validation Object
 * @class ValidationObjectProvinceAutocompleteElementResponse
 */
export class ValidationObjectProvinceAutocompleteElementResponse {
   pkiProvinceID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiCountryID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sProvinceNameX = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: true
   }
   sProvinceShortname = {
      type: 'string',
      pattern: /^.{1,3}$/,
      required: true
   }
   bProvinceIsactive = {
      type: 'boolean',
      required: true
   }
} 


