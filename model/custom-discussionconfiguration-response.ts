/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Custom Discussionconfiguration Object
 * @export
 * @interface CustomDiscussionconfigurationResponse
 */
export interface CustomDiscussionconfigurationResponse {
    /**
     * If the added Discussionmembership will have access to the entire history or not
     * @type {boolean}
     * @memberof CustomDiscussionconfigurationResponse
     */
    'bDiscussionconfigurationCompletehistorywhenadded': boolean;
    /**
     * If the the creation of the Discussion is allowed or not
     * @type {boolean}
     * @memberof CustomDiscussionconfigurationResponse
     */
    'bDiscussionconfigurationCreateallowed': boolean;
    /**
     * If the the destruction of the Discussion is allowed or not
     * @type {boolean}
     * @memberof CustomDiscussionconfigurationResponse
     */
    'bDiscussionconfigurationDeleteallowed': boolean;
    /**
     * If the the destruction of the Discussionmessage is allowed or not
     * @type {boolean}
     * @memberof CustomDiscussionconfigurationResponse
     */
    'bDiscussionconfigurationDeletediscussionmessageallowed': boolean;
    /**
     * If the the creation of the Discussionmessage is allowed or not
     * @type {boolean}
     * @memberof CustomDiscussionconfigurationResponse
     */
    'bDiscussionconfigurationEditdiscussionmessageallowed': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomDiscussionconfigurationResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomDiscussionconfigurationResponse
 */
export class DataObjectCustomDiscussionconfigurationResponse {
   bDiscussionconfigurationCompletehistorywhenadded:boolean = false
   bDiscussionconfigurationCreateallowed:boolean = false
   bDiscussionconfigurationDeleteallowed:boolean = false
   bDiscussionconfigurationDeletediscussionmessageallowed:boolean = false
   bDiscussionconfigurationEditdiscussionmessageallowed:boolean = false
}

/**
 * @export 
 * A CustomDiscussionconfigurationResponse Validation Object
 * @class ValidationObjectCustomDiscussionconfigurationResponse
 */
export class ValidationObjectCustomDiscussionconfigurationResponse {
   bDiscussionconfigurationCompletehistorywhenadded = {
      type: 'boolean',
      required: true
   }
   bDiscussionconfigurationCreateallowed = {
      type: 'boolean',
      required: true
   }
   bDiscussionconfigurationDeleteallowed = {
      type: 'boolean',
      required: true
   }
   bDiscussionconfigurationDeletediscussionmessageallowed = {
      type: 'boolean',
      required: true
   }
   bDiscussionconfigurationEditdiscussionmessageallowed = {
      type: 'boolean',
      required: true
   }
} 


