/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Response for GET /1/ezmaxcustomer/{pksEzmaxcustomerCode}/getConfiguration
 * @export
 * @interface GlobalEzmaxcustomerGetConfigurationV1Response
 */
export interface GlobalEzmaxcustomerGetConfigurationV1Response {
    /**
     * The region code
     * @type {string}
     * @memberof GlobalEzmaxcustomerGetConfigurationV1Response
     */
    /*'sInfrastructureregionCode': string;*/
    'sInfrastructureregionCode': string;
    /**
     * The region code
     * @type {string}
     * @memberof GlobalEzmaxcustomerGetConfigurationV1Response
     */
    /*'sInfrastructureregionCodeWeb': string;*/
    'sInfrastructureregionCodeWeb': string;
    /**
     * The environment type Description
     * @type {string}
     * @memberof GlobalEzmaxcustomerGetConfigurationV1Response
     */
    /*'sInfrastructureenvironmenttypeDescription': string;*/
    'sInfrastructureenvironmenttypeDescription': string;
    /**
     * The ID of the client in Cognito
     * @type {string}
     * @memberof GlobalEzmaxcustomerGetConfigurationV1Response
     */
    /*'sCognitoClientIDExternal'?: string;*/
    'sCognitoClientIDExternal'?: string;
    /**
     * The ID of the client in Cognito
     * @type {string}
     * @memberof GlobalEzmaxcustomerGetConfigurationV1Response
     */
    /*'sCognitoClientIDEzmaxpublic': string;*/
    'sCognitoClientIDEzmaxpublic': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A GlobalEzmaxcustomerGetConfigurationV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectGlobalEzmaxcustomerGetConfigurationV1Response
 */
export class DataObjectGlobalEzmaxcustomerGetConfigurationV1Response {
   sInfrastructureregionCode:string = ''
   sInfrastructureregionCodeWeb:string = ''
   sInfrastructureenvironmenttypeDescription:string = ''
   sCognitoClientIDExternal?:string = undefined
   sCognitoClientIDEzmaxpublic:string = ''
}

/**
 * @export 
 * A GlobalEzmaxcustomerGetConfigurationV1Response Validation Object
 * @class ValidationObjectGlobalEzmaxcustomerGetConfigurationV1Response
 */
export class ValidationObjectGlobalEzmaxcustomerGetConfigurationV1Response {
   sInfrastructureregionCode = {
      type: 'string',
      required: true
   }
   sInfrastructureregionCodeWeb = {
      type: 'string',
      required: true
   }
   sInfrastructureenvironmenttypeDescription = {
      type: 'string',
      required: true
   }
   sCognitoClientIDExternal = {
      type: 'string',
      required: false
   }
   sCognitoClientIDEzmaxpublic = {
      type: 'string',
      required: true
   }
} 


